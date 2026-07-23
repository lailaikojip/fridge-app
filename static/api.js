const API_BASE = "";

async function apiFetch(url, options = {}) {
  const token = localStorage.getItem("token");
  const headers = options.headers || {};
  headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(API_BASE + url, { ...options, headers });
  return response;
}

function requireLogin() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "/static/login.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("environment_id");
  window.location.href = "/static/login.html";
}
