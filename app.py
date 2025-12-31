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
    """Categorize well-known ASNs with enhanced categories"""
    try:
        known_asns = {
            # Cloud Providers
            '15169': 'Cloud Provider',  # Google
            '16509': 'Cloud Provider',  # Amazon AWS
            '8075': 'Cloud Provider',   # Microsoft Azure
            '13335': 'Cloud Provider',  # Cloudflare
            '14061': 'Cloud Provider',  # DigitalOcean
            '31898': 'Cloud Provider',  # Oracle Cloud
            '14618': 'Cloud Provider',  # Amazon AWS
            '8068': 'Cloud Provider',   # Microsoft Azure

            # Hosting Providers
            '16276': 'Hosting Provider', # OVH
            '24940': 'Hosting Provider', # Hetzner
            '60781': 'Hosting Provider', # Leaseweb
            '12876': 'Hosting Provider', # Online.net (Scaleway)

            # Mobile Carriers
            '21928': 'Mobile Carrier',  # T-Mobile
            '20057': 'Mobile Carrier',  # AT&T Wireless
            '6167': 'Mobile Carrier',   # Verizon Wireless
            '21947': 'Mobile Carrier',  # T-Mobile US
            '12041': 'Mobile Carrier',  # AT&T Wireless

            # Residential ISPs
            '7018': 'Residential',   # AT&T
            '701': 'Residential',    # Verizon
            '7922': 'Residential',   # Comcast
            '22773': 'Residential',  # Cox Communications
            '11427': 'Residential',  # Time Warner Cable
            '20115': 'Residential',  # Charter Communications
            '7011': 'Residential',   # Frontier Communications
            '12271': 'Residential',  # Time Warner Cable

            # VPN Providers
            '138997': 'VPN',         # ExpressVPN
            '48721': 'VPN',          # Mullvad VPN

            # Corporate
            '10310': 'Corporate',    # Yahoo!
            '36646': 'Corporate',    # Yahoo
            '17012': 'Corporate',    # PayPal

            # Educational
            '73': 'Educational',     # University of Washington
            '17': 'Educational',     # Purdue University
            '18': 'Educational',     # University of Texas
            '25': 'Educational',     # University of California
        }

        return known_asns.get(str(asn_num), "Other/Unknown")
    except:
        return "Other/Unknown"


def categorize_asn(name):
    """Categorize ASN based on organization name with enhanced categories"""
    try:
        name_lower = name.lower()

        # Cloud providers
        if any(word in name_lower for word in ['amazon', 'aws', 'google', 'microsoft', 'azure', 'cloudflare', 'digitalocean', 'linode', 'oracle cloud', 'ibm cloud']):
            return "Cloud Provider"

        # Hosting providers
        if any(word in name_lower for word in ['hosting', 'host', 'vps', 'dedicated', 'server', 'datacenter', 'colo', 'leaseweb', 'ovh', 'hetzner']):
            return "Hosting Provider"

        # Mobile carriers
        if any(word in name_lower for word in ['tmobile', 'verizon wireless', 'at&t wireless', 'sprint', 'vodafone', 'orange', 'telecom', 'mobile', 'cellular']):
            return "Mobile Carrier"

        # VPN providers
        if any(word in name_lower for word in ['expressvpn', 'nordvpn', 'mullvad', 'protonvpn', 'surfshark', 'private internet access', 'pia']):
            return "VPN"

        # Corporate/Enterprise
        if any(word in name_lower for word in ['corporate', 'enterprise', 'business', 'inc', 'ltd', 'corp', 'llc', 'company']):
            return "Corporate"

        # Residential ISPs (major ones)
        if any(word in name_lower for word in ['comcast', 'verizon', 'att', 'cox', 'spectrum', 'centurylink', 'charter', 'optimum', 'mediacom']):
            return "Residential"

        # Educational
        if any(word in name_lower for word in ['university', 'college', 'edu', 'school', 'academy', 'institute']):
            return "Educational"

        # Government
        if any(word in name_lower for word in ['government', 'gov', 'ministry', 'department', 'state', 'federal']):
            return "Government"

        return "Other/Unknown"
    except:
        return "Other/Unknown"


def detect_cloudflare_and_proxies(request):
    """Enhanced detection of Cloudflare and other proxy/CDN services"""
    headers = request.headers

    # Cloudflare specific headers
    cf_headers = [
        'CF-Connecting-IP',      # Original client IP
        'CF-IPCountry',          # Country code
        'CF-RAY',                # Cloudflare ray ID
        'CF-Visitor',            # Visitor scheme (http/https)
        'CF-Worker',             # Cloudflare Worker
    ]

    cloudflare_detected = any(headers.get(header) for header in cf_headers)

    # Other CDN/Proxy headers
    other_proxy_headers = [
        'X-Forwarded-For',       # Generic proxy header
        'X-Real-IP',             # Nginx real IP
        'X-Client-IP',           # Some proxies
        'X-Forwarded-Proto',     # Protocol forwarding
        'X-Forwarded-Host',      # Host forwarding
    ]

    proxy_detected = any(headers.get(header) for header in other_proxy_headers)

    # Get the real client IP considering proxies
    real_ip = None
    if headers.get('CF-Connecting-IP'):
        real_ip = headers.get('CF-Connecting-IP')
    elif headers.get('X-Real-IP'):
        real_ip = headers.get('X-Real-IP')
    elif headers.get('X-Forwarded-For'):
        # Take the first (original) IP from the chain
        real_ip = headers.get('X-Forwarded-For').split(',')[0].strip()

    return {
        'cloudflare_detected': cloudflare_detected,
        'proxy_detected': proxy_detected,
        'real_client_ip': real_ip,
        'proxy_type': 'Cloudflare' if cloudflare_detected else ('Proxy/CDN' if proxy_detected else 'Direct')
    }


def enhanced_vpn_detection(info, asn_category, proxy_info):
    """Enhanced VPN detection with inference logic"""
    vpn_detected = info.get("security", {}).get("vpn") if "security" in info else None

    # If API already detected VPN, trust it
    if vpn_detected:
        return {
            'detected': True,
            'confidence': 'High',
            'method': 'API Detection',
            'reason': 'IP geolocation service flagged as VPN'
        }

    # Inference logic: If residential ISP + residential ASN + no proxy, likely not VPN
    isp_name = info.get("org", "").lower()
    residential_indicators = [
        'comcast', 'verizon', 'att', 'cox', 'spectrum', 'centurylink',
        'charter', 'optimum', 'mediacom', 'frontier'
    ]

    is_residential_isp = any(indicator in isp_name for indicator in residential_indicators)
    is_residential_asn = asn_category == "Residential"

    if is_residential_isp and is_residential_asn and not proxy_info['proxy_detected']:
        return {
            'detected': False,
            'confidence': 'Medium',
            'method': 'Inference',
            'reason': 'Residential ISP + Residential ASN + Direct connection suggests non-VPN'
        }

    # Check for known VPN ASNs
    if asn_category == "VPN":
        return {
            'detected': True,
            'confidence': 'High',
            'method': 'ASN Analysis',
            'reason': 'Known VPN provider ASN'
        }

    # Check for suspicious patterns
    if proxy_info['proxy_detected'] and not proxy_info['cloudflare_detected']:
        return {
            'detected': True,
            'confidence': 'Low',
            'method': 'Proxy Detection',
            'reason': 'Non-Cloudflare proxy detected, possible VPN'
        }

    return {
        'detected': None,  # Unknown
        'confidence': 'Low',
        'method': 'Insufficient Data',
        'reason': 'Cannot determine VPN status'
    }


def annotate_ip(ip):
    """Annotate an IP address with basic information for display"""
    try:
        # Skip lookup for private IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return "Private/Local IP"

        # Quick lookup (cached)
        info = lookup_ip_info(ip)
        if info.get('error'):
            return "Lookup failed"

        # Format annotation
        parts = []
        if info.get('city'):
            parts.append(info['city'])
        if info.get('org'):
            parts.append(info['org'])
        if info.get('asn'):
            parts.append(info['asn'])

        return " - ".join(parts) if parts else "Unknown"
    except Exception as e:
        return f"Error: {str(e)}"


def get_ip_coordinates(ip):
    """Get geographic coordinates for an IP address"""
    try:
        # Skip lookup for private IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return None  # No coordinates for private IPs

        # Check cache first
        cache_key = f"coords_{ip}"
        if cache_key in ip_cache:
            cached_time, cached_coords = ip_cache[cache_key]
            if datetime.now() - cached_time < CACHE_DURATION:
                return cached_coords

        # Use ipwho.is API for coordinates
        url = f"http://ipwho.is/{ip}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("latitude") and data.get("longitude"):
                coords = {
                    "lat": data["latitude"],
                    "lng": data["longitude"],
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "org": data.get("connection", {}).get("org", "Unknown")
                }
                ip_cache[cache_key] = (datetime.now(), coords)
                return coords

    except Exception as e:
        print(f"Coordinate lookup failed for {ip}: {e}")

    return None


def classify_hop(ip, info, asn_category):
    """Classify a network hop for map styling"""
    try:
        # Private/local IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return {
                "type": "local",
                "icon": "home",
                "color": "#808080",
                "description": "Local/Private Network"
            }

        # Cloudflare detection
        if info.get('proxy_analysis', {}).get('cloudflare_detected'):
            return {
                "type": "cloudflare",
                "icon": "shield",
                "color": "#ff6b35",
                "description": "Cloudflare Protected"
            }

        # VPN detection
        vpn_analysis = info.get('vpn_analysis', {})
        if vpn_analysis.get('detected') == True:
            return {
                "type": "vpn",
                "icon": "eye-slash",
                "color": "#dc3545",
                "description": "VPN Detected"
            }

        # ASN-based classification
        if asn_category == "Residential":
            return {
                "type": "residential",
                "icon": "home",
                "color": "#28a745",
                "description": "Residential ISP"
            }
        elif asn_category == "Cloud Provider":
            return {
                "type": "cloud",
                "icon": "cloud",
                "color": "#007bff",
                "description": "Cloud Provider"
            }
        elif asn_category == "Hosting Provider":
            return {
                "type": "hosting",
                "icon": "server",
                "color": "#6f42c1",
                "description": "Hosting Provider"
            }
        elif asn_category == "Mobile Carrier":
            return {
                "type": "mobile",
                "icon": "signal",
                "color": "#fd7e14",
                "description": "Mobile Carrier"
            }
        elif asn_category == "Corporate":
            return {
                "type": "corporate",
                "icon": "building",
                "color": "#6c757d",
                "description": "Corporate Network"
            }
        elif asn_category == "VPN":
            return {
                "type": "vpn",
                "icon": "eye-slash",
                "color": "#dc3545",
                "description": "VPN Provider"
            }

        # Default
        return {
            "type": "unknown",
            "icon": "question",
            "color": "#ffc107",
            "description": "Unknown/Other"
        }

    except Exception as e:
        print(f"Error classifying hop {ip}: {e}")
        return {
            "type": "error",
            "icon": "exclamation-triangle",
            "color": "#dc3545",
            "description": "Classification Error"
        }


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
        # Enhanced proxy and Cloudflare detection
        proxy_info = detect_cloudflare_and_proxies(request)

        # Use real client IP if available (behind Cloudflare/proxy)
        raw_chain = request.headers.get("X-Forwarded-For") or request.remote_addr
        chain = [ip.strip() for ip in raw_chain.split(",")]
        annotated_chain = [(hop, annotate_ip(hop)) for hop in chain]

        # Use the real client IP for lookups
        ip = proxy_info['real_client_ip'] or chain[0]
        session["name"] = ip

        # Basic IP info lookup with error handling
        info = {}
        try:
            info = lookup_ip_info(ip)
        except Exception as e:
            print(f"IP lookup error: {e}")
            info = {"error": "IP lookup failed"}

        # Enhanced VPN detection
        asn_category = "Unknown"
        if info.get("asn_info"):
            asn_category = info["asn_info"].get("type", "Unknown")
        elif info.get("asn"):
            asn_category = categorize_known_asn(info["asn"].replace("AS", ""))

        vpn_analysis = enhanced_vpn_detection(info, asn_category, proxy_info)

        # Add enhanced analysis to info
        info['proxy_analysis'] = proxy_info
        info['vpn_analysis'] = vpn_analysis
        info['asn_category'] = asn_category

        # Enhanced chain analysis with coordinates and classification
        enhanced_chain = []
        for hop_ip in chain:
            hop_info = lookup_ip_info(hop_ip) if not hop_ip.startswith(('127.', '192.168.', '10.', '172.')) else {"error": "Private IP"}
            hop_asn_category = "Unknown"
            if hop_info.get("asn_info"):
                hop_asn_category = hop_info["asn_info"].get("type", "Unknown")
            elif hop_info.get("asn"):
                hop_asn_category = categorize_known_asn(hop_info["asn"].replace("AS", ""))

            hop_coords = get_ip_coordinates(hop_ip)
            hop_classification = classify_hop(hop_ip, info if hop_ip == ip else hop_info, hop_asn_category)

            enhanced_chain.append({
                "ip": hop_ip,
                "label": annotate_ip(hop_ip),
                "coords": hop_coords,
                "classification": hop_classification,
                "info": hop_info
            })

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
                        json.dumps({
                            'name': info.get('asn_info', {}).get('name'),
                            'type': info.get('asn_category'),
                            'country': info.get('asn_info', {}).get('country')
                        }) if info.get('asn_info') or info.get('asn_category') else None,
                        json.dumps(info.get('vpn_analysis')) if info.get('vpn_analysis') else None,
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
            chain=annotated_chain,  # Keep original for backward compatibility
            enhanced_chain=enhanced_chain,  # New enhanced data for map
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
                                asn_data = json.loads(row["asn_info"])
                                visitor["info"]["asn_info"] = asn_data
                                visitor["info"]["asn_category"] = asn_data.get("type", "Unknown")
                            except:
                                pass

                        # Add VPN analysis if available
                        if row.get("vpn"):
                            try:
                                vpn_data = json.loads(row["vpn"])
                                visitor["info"]["vpn_analysis"] = vpn_data
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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
