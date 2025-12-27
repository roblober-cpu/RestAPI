from flask import Flask, request, session, render_template
import requests

app = Flask(__name__)
app.secret_key = "your-secret-key"

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

def lookup_ip_info(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.json()
        return {}
    except Exception:
        return {}

@app.before_request
def assign_ip_as_username():
    if "username" not in session:
        session["username"] = get_client_ip()

@app.route("/")
def home():
    ip = session.get("username", "Unknown")
    info = lookup_ip_info(ip)
    return render_template("index.html", name=ip, info=info)
from flask import Flask, request, session, render_template
import requests


#Deploy
if __name__ == "__main__":
    #Listen on all interfaces, port 5000
    app.run(host="0.0.0.0", port=5000)

