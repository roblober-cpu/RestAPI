from flask import Flask, request, session, render_template
import requests
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "your-secret-key"

# Fallback in-memory storage if database is not available
visitors_fallback = []

# Database connection from environment variable
DATABASE_URL = os.environ.get("DATABASE_URL")

# Simple in-memory cache for IP lookups (resets on restart)
ip_cache = {}
CACHE_DURATION = timedelta(hours=1)  # Cache results for 1 hour

# Optional database support
try:
    import psycopg2
    import psycopg2.extras
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    print("Warning: psycopg2 not available, running without database")

def get_db_connection():
    """Create a database connection"""
    if not DB_AVAILABLE or not DATABASE_URL:
        return None
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def init_db():
    """Initialize database schema"""
    if not DB_AVAILABLE or not DATABASE_URL:
        print("Database not configured, skipping initialization")
        return

    conn = get_db_connection()
    if not conn:
        return

    try:
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
    except Exception as e:
        print(f"Database initialization error: {e}")

# Try to initialize database
try:
    init_db()
except Exception as e:
    print(f"Database initialization error: {e}")
    # Continue running even if DB init fails



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
                    try:
                        asn_info = lookup_asn_info(result["asn"])
                        if asn_info:
                            result["asn_info"] = asn_info
                    except Exception as e:
                        print(f"ASN lookup error for {result['asn']}: {e}")
                        # Continue without ASN info rather than failing

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
            try:
                if 'Organization:' in html:
                    start = html.find('Organization:') + len('Organization:')
                    end = html.find('<', start)
                    if end > start:
                        asn_info['name'] = html[start:end].strip()
            except:
                pass

            # Extract country
            try:
                if 'Country:' in html:
                    start = html.find('Country:') + len('Country:')
                    end = html.find('<', start)
                    if end > start:
                        asn_info['country'] = html[start:end].strip()
            except:
                pass

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
    try:
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

        return known_asns.get(str(asn_num), "Other/Unknown")
    except:
        return "Other/Unknown"


def categorize_asn(name):
    """Categorize ASN based on organization name"""
    try:
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
    except:
        return "Other/Unknown"


def annotate_ip(ip):
    """Annotate an IP address with network information"""
    try:
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
    except:
        return "Unknown"


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

@app.route("/test")
def test():
    return "<h1>App is working!</h1><p>If you can see this, the basic Flask app is running.</p>"

@app.route("/")
def index():
    try:
        raw_chain = request.headers.get("X-Forwarded-For") or request.remote_addr
        chain = [ip.strip() for ip in raw_chain.split(",")]
        annotated_chain = [(hop, annotate_ip(hop)) for hop in chain]

        ip = chain[0]
        session["name"] = ip

        # Basic IP info lookup with error handling
        info = {}
        try:
            info = lookup_ip_info(ip)
        except Exception as e:
            print(f"IP lookup error: {e}")
            info = {"error": "IP lookup failed"}

        # Log visitor (database optional)
        if DB_AVAILABLE and DATABASE_URL:
            try:
                conn = get_db_connection()
                if conn:
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
                print(f"Database error logging visitor: {e}")

        # Fallback: always store in memory for immediate access
        visitor_record = {
            "ip": ip,
            "info": info.copy(),
            "chain": annotated_chain,
            "timestamp": datetime.utcnow()
        }
        visitors_fallback.append(visitor_record)
        # Keep only last 100 visitors in memory
        if len(visitors_fallback) > 100:
            visitors_fallback.pop(0)

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
    except Exception as e:
        print(f"Unexpected error in index route: {e}")
        # Return a basic error page
        return f"<h1>Error</h1><p>Something went wrong: {str(e)}</p>", 500


@app.route("/dashboard")
def dashboard():
    try:
        visitors = []

        if DB_AVAILABLE and DATABASE_URL:
            try:
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                    cursor.execute("SELECT * FROM visitors ORDER BY timestamp DESC")
                    rows = cursor.fetchall()
                    cursor.close()
                    conn.close()

                    # Convert rows to dictionaries with parsed chain data
                    for row in rows:
                        try:
                            chain_data = json.loads(row["chain"]) if row["chain"] else []
                        except:
                            chain_data = []

                        visitor = {
                            "ip": row["ip"],
                            "info": {
                                "city": row["city"],
                                "region": row["region"],
                                "country": row["country"],
                                "org": row["org"],
                                "asn": row["asn"],
                            },
                            "chain": chain_data,
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
                print(f"Database error loading visitors: {e}")
                # Fall back to in-memory storage
                visitors = visitors_fallback.copy()
        else:
            # No database available, use in-memory storage
            visitors = visitors_fallback.copy()

        return render_template("dashboard.html", visitors=visitors)
    except Exception as e:
        print(f"Unexpected error in dashboard route: {e}")
        return f"<h1>Dashboard Error</h1><p>Something went wrong: {str(e)}</p>", 500
