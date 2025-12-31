from flask import Flask, request, session, render_template
import requests
import psycopg2
import psycopg2.extras
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "your-secret-key"

# Database connection from environment variable
DATABASE_URL = os.environ.get("DATABASE_URL")

# Simple in-memory cache for IP lookups (resets on restart)
ip_cache = {}
CACHE_DURATION = timedelta(hours=1)  # Cache results for 1 hour

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
            asn_info TEXT,
            vpn TEXT,
            chain TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add asn_info column if it doesn't exist (for existing databases)
    try:
        cursor.execute("ALTER TABLE visitors ADD COLUMN IF NOT EXISTS asn_info TEXT")
        conn.commit()
    except Exception as e:
        print(f"Column addition warning: {e}")
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
    # Check cache first
    if ip in ip_cache:
        cached_time, cached_data = ip_cache[ip]
        if datetime.now() - cached_time < CACHE_DURATION:
            return cached_data
        else:
            # Cache expired, remove it
            del ip_cache[ip]

    # Skip lookup for private/local IPs
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        result = {"error": "Private IP - no public info available"}
        ip_cache[ip] = (datetime.now(), result)
        return result

    try:
        # Use ipwho.is API (good free tier, reliable)
        url = f"http://ipwho.is/{ip}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                # Convert to consistent format
                result = {
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("connection", {}).get("org") or data.get("connection", {}).get("isp"),
                    "asn": f"AS{data.get('connection', {}).get('asn')}" if data.get("connection", {}).get("asn") else None,
                }

                # Add ASN details if available
                if result.get("asn"):
                    asn_info = lookup_asn_info(result["asn"])
                    if asn_info:
                        result["asn_info"] = asn_info

                ip_cache[ip] = (datetime.now(), result)
                return result
            else:
                return {"error": "API returned success=false"}

    except Exception as e:
        print(f"Error looking up IP {ip}: {e}")
        return {"error": f"Lookup failed: {str(e)}"}

    # Fallback: return minimal error info
    result = {"error": "Lookup failed"}
    ip_cache[ip] = (datetime.now(), result)
    return result


def lookup_asn_info(asn):
    """Look up ASN information to identify the network operator"""
    if not asn:
        return None

    # Clean ASN (remove 'AS' prefix if present)
    asn_num = asn.replace('AS', '') if asn.startswith('AS') else asn

    try:
        # Use BGP.HE.NET for ASN lookup (reliable and free)
        url = f"https://bgp.he.net/AS{asn_num}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            # Parse the HTML response for ASN info
            html = response.text
            asn_info = {}

            # Extract organization name
            if 'Organization:' in html:
                start = html.find('Organization:') + len('Organization:')
                end = html.find('<', start)
                if end > start:
                    asn_info['name'] = html[start:end].strip()

            # Extract country
            if 'Country:' in html:
                start = html.find('Country:') + len('Country:')
                end = html.find('<', start)
                if end > start:
                    asn_info['country'] = html[start:end].strip()

            if asn_info:
                asn_info['type'] = categorize_asn(asn_info.get('name', '').lower())
                return asn_info

    except Exception as e:
        print(f"ASN lookup failed for {asn}: {e}")

    # Fallback: categorize based on known ASNs
    return {
        "name": f"AS{asn_num}",
        "description": "Unknown ASN",
        "country": "Unknown",
        "type": categorize_known_asn(asn_num)
    }


def categorize_known_asn(asn_num):
    """Categorize well-known ASNs"""
    known_asns = {
        # Cloud Providers
        '15169': 'Cloud Provider',  # Google
        '16509': 'Cloud Provider',  # Amazon AWS
        '8075': 'Cloud Provider',   # Microsoft Azure
        '13335': 'Cloud Provider',  # Cloudflare
        '14061': 'Cloud Provider',  # DigitalOcean
        '31898': 'Cloud Provider',  # Oracle Cloud

        # Major ISPs
        '7018': 'Major ISP',   # AT&T
        '701': 'Major ISP',    # Verizon
        '7922': 'Major ISP',   # Comcast
        '22773': 'Major ISP',  # Cox Communications
        '11427': 'Major ISP',  # Time Warner Cable
        '20115': 'Major ISP',  # Charter Communications

        # Mobile Carriers
        '21928': 'Mobile Carrier',  # T-Mobile
        '20057': 'Mobile Carrier',  # AT&T Wireless
        '6167': 'Mobile Carrier',   # Verizon Wireless

        # Universities
        '73': 'Educational',    # University of Washington
        '17': 'Educational',    # Purdue University
        '18': 'Educational',    # University of Texas
    }

    return known_asns.get(asn_num, "Other/Unknown")


def categorize_asn(name):
    """Categorize ASN based on organization name"""
    name_lower = name.lower()

    # Cloud providers
    if any(word in name_lower for word in ['amazon', 'aws', 'google', 'microsoft', 'azure', 'cloudflare', 'digitalocean', 'linode']):
        return "Cloud Provider"

    # Major ISPs
    if any(word in name_lower for word in ['comcast', 'verizon', 'att', 'cox', 'spectrum', 'centurylink', 'telecom']):
        return "Major ISP"

    # Mobile carriers
    if any(word in name_lower for word in ['tmobile', 'verizon wireless', 'at&t wireless', 'sprint', 'vodafone', 'orange']):
        return "Mobile Carrier"

    # Universities/Education
    if any(word in name_lower for word in ['university', 'college', 'edu', 'school', 'academy']):
        return "Educational"

    # Government
    if any(word in name_lower for word in ['government', 'gov', 'ministry', 'department', 'state']):
        return "Government"

    # Hosting/VPS
    if any(word in name_lower for word in ['hosting', 'host', 'vps', 'dedicated', 'server']):
        return "Hosting Provider"

    return "Other/Unknown"


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
            INSERT INTO visitors (ip, city, region, country, org, asn, asn_info, vpn, chain)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            ip,
            info.get("city"),
            info.get("region"),
            info.get("country"),
            info.get("org"),
            info.get("asn"),
            json.dumps(info.get("asn_info")) if info.get("asn_info") else None,
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
            # Add ASN info if available
            if row["asn_info"]:
                try:
                    visitor["info"]["asn_info"] = json.loads(row["asn_info"])
                except:
                    pass
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
