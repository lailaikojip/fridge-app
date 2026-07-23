import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_whatsapp_alert(to_number: str, item_name: str, days_stored: int) -> dict:
    """
    Sends a WhatsApp aging alert to a room's registered phone number.
    to_number should be in E.164 format, e.g. '+85291234567'
    """
    try:
        message = client.messages.create(
            from_=TWILIO_WHATSAPP_FROM,
            to=f"whatsapp:{to_number}",
            body=f"Reminder: your item '{item_name}' has been in the fridge for {days_stored} days. Please remove it soon!"
        )
        return {"success": True, "sid": message.sid}
    except Exception as e:
        return {"success": False, "error": str(e)}