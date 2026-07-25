var API_BASE = "";

async function apiFetch(url, options) {
  options = options || {};
  var token = localStorage.getItem("token");
  var headers = options.headers || {};
  headers["Content-Type"] = "application/json";
  if (token) {
    headers["Authorization"] = "Bearer " + token;
  }
  options.headers = headers;

  var response = await fetch(API_BASE + url, options);
  return response;
}

function requireLogin() {
  var token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "/static/login.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("environment_id");
  window.location.href = "/static/login.html";
}
