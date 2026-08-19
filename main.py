import os
from fastapi import FastAPI, HTTPException, Request, Header, Depends
from pydantic import BaseModel
import psycopg2
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional, List
from notifications import send_whatsapp_alert
from fastapi.staticfiles import StaticFiles

import jwt
import bcrypt

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
CRON_SECRET = os.getenv("CRON_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET")


def get_connection():
    return psycopg2.connect(DATABASE_URL)


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------- Password hashing helpers ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# ---------- JWT token helpers ----------
def create_token(admin_id: int) -> str:
    payload = {
        "admin_id": admin_id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_admin(authorization: str = Header(...)) -> int:
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["admin_id"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or missing token")


def check_admin_access(cursor, admin_id: int, environment_id: int):
    cursor.execute(
        "SELECT 1 FROM environment_admins WHERE admin_id = %s AND environment_id = %s;",
        (admin_id, environment_id)
    )
    if cursor.fetchone() is None:
        raise HTTPException(status_code=403, detail="You do not have access to this environment")


# ---------- Admin signup + login ----------
class SignupRequest(BaseModel):
    email: str
    password: str


@app.post("/api/admin/signup")
def signup(data: SignupRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT admin_id FROM admins WHERE email = %s;", (data.email,))
    if cursor.fetchone() is not None:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = hash_password(data.password)
    cursor.execute(
        "INSERT INTO admins (email, password_hash) VALUES (%s, %s) RETURNING admin_id;",
        (data.email, password_hash)
    )
    admin_id = cursor.fetchone()[0]

    conn.commit()
    cursor.close()
    conn.close()

    token = create_token(admin_id)
    return {"success": True, "token": token}


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/admin/login")
def login(data: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT admin_id, password_hash FROM admins WHERE email = %s;", (data.email,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    admin_id, password_hash = row

    if not verify_password(data.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(admin_id)
    return {"success": True, "token": token}


# ---------- Environment creation + admin management ----------
class CreateEnvironmentRequest(BaseModel):
    name: str
    notification_threshold_days: Optional[int] = 30


@app.post("/api/environments/create")
def create_environment(data: CreateEnvironmentRequest, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO environments (name, notification_threshold_days) VALUES (%s, %s) RETURNING environment_id;",
        (data.name, data.notification_threshold_days)
    )
    environment_id = cursor.fetchone()[0]

    cursor.execute(
        "INSERT INTO environment_admins (environment_id, admin_id) VALUES (%s, %s);",
        (environment_id, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True, "environment_id": environment_id}


@app.get("/api/environments/mine")
def list_my_environments(admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT environments.environment_id, environments.name, environments.notification_threshold_days
        FROM environments
        JOIN environment_admins ON environments.environment_id = environment_admins.environment_id
        WHERE environment_admins.admin_id = %s
        ORDER BY environments.environment_id ASC;
        """,
        (admin_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    environments = []
    for environment_id, name, threshold in rows:
        environments.append({
            "environment_id": environment_id,
            "name": name,
            "notification_threshold_days": threshold
        })

    return {"environments": environments}


class AddAdminRequest(BaseModel):
    email: str


@app.post("/api/environments/{environment_id}/add-admin")
def add_admin(environment_id: int, data: AddAdminRequest, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    cursor.execute("SELECT admin_id FROM admins WHERE email = %s;", (data.email,))
    row = cursor.fetchone()
    if row is None:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="No admin account found for that email. They need to sign up first.")

    new_admin_id = row[0]

    cursor.execute(
        "INSERT INTO environment_admins (environment_id, admin_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
        (environment_id, new_admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True, "message": data.email + " added as admin"}


# ---------- Environment settings + room bulk import ----------
@app.get("/api/environments/{environment_id}/settings")
def get_settings(environment_id: int, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    cursor.execute(
        "SELECT name, notification_threshold_days FROM environments WHERE environment_id = %s;",
        (environment_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Environment not found")

    name, threshold = row
    return {"name": name, "notification_threshold_days": threshold}


class UpdateSettingsRequest(BaseModel):
    notification_threshold_days: int


@app.put("/api/environments/{environment_id}/settings")
def update_settings(environment_id: int, data: UpdateSettingsRequest, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    cursor.execute(
        "UPDATE environments SET notification_threshold_days = %s WHERE environment_id = %s;",
        (data.notification_threshold_days, environment_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True}


class RoomEntry(BaseModel):
    room_id: str
    phone_number: str


class BulkImportRequest(BaseModel):
    rooms: List[RoomEntry]


@app.post("/api/environments/{environment_id}/rooms/bulk-import")
def bulk_import_rooms(environment_id: int, data: BulkImportRequest, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    for room in data.rooms:
        cursor.execute(
            """
            INSERT INTO rooms (room_id, phone_number, environment_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (room_id, environment_id) DO UPDATE SET phone_number = EXCLUDED.phone_number;
            """,
            (room.room_id, room.phone_number, environment_id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True, "count": len(data.rooms)}


# ---------- Items: add / remove / list per fridge ----------
class AddItemRequest(BaseModel):
    environment_id: int
    fridge_id: int
    room_id: str
    item_name: str


@app.post("/api/items/add")
def add_item(data: AddItemRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT room_id FROM rooms WHERE room_id = %s AND environment_id = %s;",
        (data.room_id, data.environment_id)
    )
    if cursor.fetchone() is None:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Room ID not found in this environment")

    cursor.execute(
        """
        INSERT INTO items (room_id, fridge_id, item_name, date_added, environment_id)
        VALUES (%s, %s, %s, NOW(), %s);
        """,
        (data.room_id, data.fridge_id, data.item_name, data.environment_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True}


class RemoveRequest(BaseModel):
    item_id: int


@app.post("/api/remove")
def remove_item(data: RemoveRequest):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT item_id FROM items WHERE item_id = %s AND date_removed IS NULL;",
        (data.item_id,)
    )
    if cursor.fetchone() is None:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="No active item found with this ID")

    cursor.execute("UPDATE items SET date_removed = NOW() WHERE item_id = %s;", (data.item_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return {"success": True, "message": "Item removed"}


@app.get("/api/fridge-items")
def get_fridge_items(environment_id: int, fridge_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT item_id, room_id, item_name, date_added
        FROM items
        WHERE environment_id = %s AND fridge_id = %s AND date_removed IS NULL
        ORDER BY date_added ASC;
        """,
        (environment_id, fridge_id)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    items = []
    for item_id, room_id, item_name, date_added in rows:
        days_stored = (datetime.now() - date_added).days
        items.append({
            "item_id": item_id,
            "room_id": room_id,
            "item_name": item_name,
            "days_stored": days_stored
        })

    return {"items": items}


# ---------- Admin inventory view (all items, room_id hidden) ----------
@app.get("/api/inventory")
def get_inventory(
    environment_id: int,
    fridge_id: Optional[int] = None,
    admin_id: int = Depends(get_current_admin)
):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    if fridge_id is not None:
        cursor.execute(
            """
            SELECT item_name, date_added, fridge_id
            FROM items
            WHERE environment_id = %s AND date_removed IS NULL AND fridge_id = %s
            ORDER BY date_added ASC;
            """,
            (environment_id, fridge_id)
        )
    else:
        cursor.execute(
            """
            SELECT item_name, date_added, fridge_id
            FROM items
            WHERE environment_id = %s AND date_removed IS NULL
            ORDER BY date_added ASC;
            """,
            (environment_id,)
        )

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    items = []
    for item_name, date_added, fridge_id_val in rows:
        days_stored = (datetime.now() - date_added).days
        items.append({
            "item_name": item_name,
            "date_added": date_added,
            "days_stored": days_stored,
            "fridge_id": fridge_id_val
        })

    return {"items": items}


# ---------- Fridge-full ranking ----------
@app.get("/api/fridge-full-ranking")
def fridge_full_ranking(environment_id: int, fridge_id: int, admin_id: int = Depends(get_current_admin)):
    conn = get_connection()
    cursor = conn.cursor()

    check_admin_access(cursor, admin_id, environment_id)

    cursor.execute(
        """
        SELECT room_id, date_added
        FROM items
        WHERE environment_id = %s AND fridge_id = %s AND date_removed IS NULL;
        """,
        (environment_id, fridge_id)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    room_data = {}
    for room_id, date_added in rows:
        days = (datetime.now() - date_added).days
        if room_id not in room_data:
            room_data[room_id] = {"x": 0, "T": 0}
        room_data[room_id]["x"] += 1
        room_data[room_id]["T"] += days

    ranking = []
    for room_id, data in room_data.items():
        x = data["x"]
        T = data["T"]
        y = (88 / x) + (12 * x)
        point = (y / 100) * T
        ranking.append({
            "room_id": room_id,
            "item_count": x,
            "total_days": T,
            "point": round(point, 2)
        })

    ranking.sort(key=lambda r: r["point"], reverse=True)
    return {"fridge_id": fridge_id, "ranking": ranking}


# ---------- Aging check / WhatsApp alerts ----------
def send_whatsapp_for_environment_check():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT environment_id, notification_threshold_days FROM environments;")
    environments = cursor.fetchall()

    all_results = []

    for environment_id, threshold in environments:
        cursor.execute(
            """
            SELECT items.item_id, items.item_name, items.date_added, rooms.phone_number
            FROM items
            JOIN rooms ON items.room_id = rooms.room_id AND rooms.environment_id = items.environment_id
            WHERE items.environment_id = %s
            AND items.date_removed IS NULL
            AND items.notified = false
            AND rooms.phone_number IS NOT NULL
            AND items.date_added < NOW() - (%s || ' days')::INTERVAL;
            """,
            (environment_id, threshold)
        )
        overdue_items = cursor.fetchall()

        for item_id, item_name, date_added, phone_number in overdue_items:
            days_stored = (datetime.now() - date_added).days
            send_result = send_whatsapp_alert(phone_number, item_name, days_stored)

            if send_result["success"]:
                cursor.execute("UPDATE items SET notified = true WHERE item_id = %s;", (item_id,))

            all_results.append({
                "environment_id": environment_id,
                "item_id": item_id,
                "item_name": item_name,
                "sent": send_result["success"]
            })

    conn.commit()
    cursor.close()
    conn.close()
    return all_results


@app.post("/api/run-aging-check")
def run_aging_check(request: Request):
    auth_header = request.headers.get("authorization")
    if auth_header != "Bearer " + str(CRON_SECRET):
        raise HTTPException(status_code=401, detail="Unauthorized")

    results = send_whatsapp_for_environment_check()
    return {"results": results}