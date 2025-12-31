from flask import Flask, request, session, render_template
import requests
import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your-secret-key"

# Database connection from environment variable
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    """Create a database connection"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Initialize database schema"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS visitors (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            city TEXT,
            region TEXT,
            country TEXT,
            org TEXT,
            asn TEXT,
            vpn TEXT,
            chain TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

try:
    init_db()
except Exception as e:
    print(f"Database initialization warning: {e}")



# -----------------------------
#  IP + Network Utilities
# -----------------------------

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


def annotate_ip(ip):
    # Private ranges
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        # More accurate private range check
        parts = ip.split(".")
        if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return "Private Network / Load Balancer"
        if parts[0] in ("10", "192"):
            return "Private Network / Load Balancer"

    # Cloudflare
    if ip.startswith(("104.", "172.64.", "188.114.")):
        return "Cloudflare Edge Node"

    # AWS
    if ip.startswith(("3.", "13.", "18.", "34.", "35.", "52.", "54.")):
        return "AWS Cloud Server"

    # Google Cloud
    if ip.startswith(("34.", "35.", "66.102.", "66.249.")):
        return "Google Cloud Server"

    # Azure
    if ip.startswith(("20.", "40.", "52.", "104.")):
        return "Azure Cloud Server"

    # Starlink
    if ip.startswith("100."):
        return "Starlink CGNAT"

    # Generic VPN ranges (very rough)
    if ip.startswith(("5.", "37.", "45.", "91.", "95.", "185.")):
        return "Possible VPN Provider"

    return "Public Client or Unknown Proxy"


# -----------------------------
#  Session Setup
# -----------------------------

@app.before_request
def assign_ip_as_username():
    if "username" not in session:
        session["username"] = get_client_ip()


# -----------------------------
#  Routes
# -----------------------------

@app.route("/")
def index():
    raw_chain = request.headers.get("X-Forwarded-For") or request.remote_addr
    chain = [ip.strip() for ip in raw_chain.split(",")]
    annotated_chain = [(hop, annotate_ip(hop)) for hop in chain]

    ip = chain[0]
    session["name"] = ip

    info = lookup_ip_info(ip)

    # Log visitor to database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO visitors (ip, city, region, country, org, asn, vpn, chain)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            ip,
            info.get("city"),
            info.get("region"),
            info.get("country"),
            info.get("org"),
            info.get("asn"),
            info.get("security", {}).get("vpn") if "security" in info else None,
            json.dumps(annotated_chain)
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error logging visitor: {e}")

    return render_template(
        "index.html",
        info=info,
        name=ip,
        chain=annotated_chain,
        city=info.get("city"),
        region=info.get("region"),
        country=info.get("country"),
        isp=info.get("org"),
        asn=info.get("asn"),
        vpn=info.get("security", {}).get("vpn") if "security" in info else None,
    )


@app.route("/dashboard")
def dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM visitors ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Convert rows to dictionaries with parsed chain data
        visitors = []
        for row in rows:
            visitor = {
                "ip": row["ip"],
                "info": {
                    "city": row["city"],
                    "region": row["region"],
                    "country": row["country"],
                    "org": row["org"],
                    "asn": row["asn"],
                },
                "chain": json.loads(row["chain"]),
                "timestamp": row["timestamp"]
            }
            visitors.append(visitor)
    except Exception as e:
        print(f"Error loading visitors: {e}")
        visitors = []
    
    return render_template("dashboard.html", visitors=visitors)


# -----------------------------
#  Deploy
# -----------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
