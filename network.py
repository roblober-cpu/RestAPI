"""
Network analysis module for IP identification, ASN categorization, and VPN detection.
"""

import requests
import json
from datetime import datetime, timedelta
from .database import db_save_visitor

# IP cache for geolocation results
ip_cache = {}
CACHE_DURATION = timedelta(hours=1)

def get_ip_info(ip):
    """Get IP geolocation and network information"""
    if ip in ip_cache:
        cached_time, cached_data = ip_cache[ip]
        if datetime.now() - cached_time < CACHE_DURATION:
            return cached_data
        else:
            del ip_cache[ip]

    try:
        # Use ipapi.co for geolocation
        response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            result = {
                'ip': ip,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'org': data.get('org'),
                'asn': data.get('asn'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude')
            }
            ip_cache[ip] = (datetime.now(), result)
            return result
    except Exception as e:
        print(f"IP info lookup error for {ip}: {e}")

    return {'ip': ip}

def get_ip_coordinates(ip):
    """Get coordinates for an IP address"""
    cache_key = f"coords_{ip}"
    if cache_key in ip_cache:
        cached_time, cached_coords = ip_cache[cache_key]
        if datetime.now() - cached_time < CACHE_DURATION:
            return cached_coords

    try:
        response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            coords = {
                'lat': data.get('latitude'),
                'lng': data.get('longitude')
            }
            ip_cache[cache_key] = (datetime.now(), coords)
            return coords
    except Exception as e:
        print(f"Coordinate lookup error for {ip}: {e}")

    return None

def categorize_asn(org_name):
    """Categorize ASN based on organization name"""
    if not org_name:
        return "Unknown"

    org_lower = org_name.lower()

    # Cloud providers
    if any(keyword in org_lower for keyword in ['google', 'amazon', 'microsoft', 'azure', 'aws']):
        return "Cloud Provider"

    # Hosting providers
    if any(keyword in org_lower for keyword in ['ovh', 'digitalocean', 'linode', 'vultr', 'hetzner']):
        return "Hosting"

    # Mobile carriers
    if any(keyword in org_lower for keyword in ['verizon', 'att', 'tmobile', 'sprint', 'vodafone']):
        return "Mobile"

    # Residential ISPs
    if any(keyword in org_lower for keyword in ['comcast', 'cox', 'spectrum', 'centurylink', 'at&t']):
        return "Residential"

    # VPN providers
    if any(keyword in org_lower for keyword in ['expressvpn', 'nordvpn', 'mullvad', 'protonvpn']):
        return "VPN"

    # Content delivery networks
    if any(keyword in org_lower for keyword in ['cloudflare', 'akamai', 'fastly', 'cdn']):
        return "CDN"

    return "Unknown"

def categorize_known_asn(asn):
    """Categorize known ASNs"""
    known_asns = {
        '15169': 'Google',
        '7922': 'Comcast',
        '21928': 'T-Mobile',
        '16276': 'OVH',
        '13335': 'Cloudflare',
        '20940': 'Akamai',
        '54113': 'Fastly'
    }
    return known_asns.get(asn, 'Unknown')

def enhanced_vpn_detection(ip_info, classification, proxy_analysis):
    """Enhanced VPN detection logic"""
    if not ip_info or not classification:
        return "Unknown"

    # Check for known VPN indicators
    org_name = ip_info.get('org', '').lower()

    # Direct VPN provider detection
    vpn_providers = ['expressvpn', 'nordvpn', 'mullvad', 'protonvpn', 'surfshark']
    if any(provider in org_name for provider in vpn_providers):
        return "VPN Detected"

    # Cloudflare detection (often used with VPNs)
    if proxy_analysis.get('cloudflare_detected'):
        return "Possible VPN"

    # Residential classification with non-residential org
    if classification == "Residential":
        residential_indicators = ['comcast', 'cox', 'spectrum', 'centurylink', 'verizon']
        if not any(indicator in org_name for indicator in residential_indicators):
            return "Possible VPN"

    # Hosting provider with residential-like behavior
    if classification == "Hosting":
        return "Possible VPN"

    return "Direct Connection"

def classify_hop(ip, analysis_info, base_classification):
    """Classify a network hop with enhanced analysis"""
    if not analysis_info:
        return {
            'ip': ip,
            'classification': {
                'category': base_classification,
                'icon': get_classification_icon(base_classification),
                'color': get_classification_color(base_classification),
                'description': get_classification_description(base_classification)
            }
        }

    # Enhanced classification logic
    enhanced_category = base_classification

    # Check for VPN indicators
    vpn_result = enhanced_vpn_detection(
        analysis_info.get('ip_info', {}),
        base_classification,
        analysis_info.get('proxy_analysis', {})
    )

    if vpn_result in ["VPN Detected", "Possible VPN"]:
        enhanced_category = "VPN"

    return {
        'ip': ip,
        'classification': {
            'category': enhanced_category,
            'icon': get_classification_icon(enhanced_category),
            'color': get_classification_color(enhanced_category),
            'description': get_classification_description(enhanced_category)
        }
    }

def get_classification_icon(category):
    """Get icon for network classification"""
    icon_map = {
        'Residential': 'home',
        'Cloud Provider': 'cloud',
        'Hosting': 'server',
        'Mobile': 'signal',
        'VPN': 'eye-slash',
        'CDN': 'shield',
        'Unknown': 'question'
    }
    return icon_map.get(category, 'question')

def get_classification_color(category):
    """Get color for network classification"""
    color_map = {
        'Residential': '#28a745',
        'Cloud Provider': '#007bff',
        'Hosting': '#6f42c1',
        'Mobile': '#fd7e14',
        'VPN': '#dc3545',
        'CDN': '#ff6b35',
        'Unknown': '#808080'
    }
    return color_map.get(category, '#808080')

def get_classification_description(category):
    """Get description for network classification"""
    desc_map = {
        'Residential': 'Home internet connection',
        'Cloud Provider': 'Major cloud computing platform',
        'Hosting': 'Web hosting or VPS provider',
        'Mobile': 'Mobile data connection',
        'VPN': 'Virtual private network',
        'CDN': 'Content delivery network',
        'Unknown': 'Unidentified network type'
    }
    return desc_map.get(category, 'Unknown network type')

def analyze_visitor_network(ip):
    """Complete network analysis for a visitor IP"""
    ip_info = get_ip_info(ip)
    if not ip_info:
        return None

    # Basic classification
    base_category = categorize_asn(ip_info.get('org'))

    # Enhanced analysis
    analysis = {
        'ip_info': ip_info,
        'proxy_analysis': {'cloudflare_detected': False},  # Placeholder
        'vpn_analysis': {'detected': False}  # Placeholder
    }

    hop_classification = classify_hop(ip, analysis, base_category)

    return {
        'ip': ip,
        'info': ip_info,
        'classification': hop_classification['classification'],
        'coordinates': {
            'lat': ip_info.get('latitude'),
            'lng': ip_info.get('longitude')
        } if ip_info.get('latitude') else None
    }

def save_visitor_data(ip, network_analysis):
    """Save visitor data to database"""
    if not network_analysis:
        return False

    return db_save_visitor(
        ip=ip,
        city=network_analysis['info'].get('city'),
        region=network_analysis['info'].get('region'),
        country=network_analysis['info'].get('country'),
        org=network_analysis['info'].get('org'),
        asn=network_analysis['info'].get('asn'),
        vpn=network_analysis['classification']['category'] if network_analysis['classification']['category'] == 'VPN' else None
    )</content>
<parameter name="filePath">/Users/robertlober/Documents/Deploy to Render/network.py