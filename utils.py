"""
Utility functions for the visitor tracking application.
"""

import re
from flask import request

def get_client_ip():
    """Get the client's real IP address"""
    # Check for forwarded header (common with proxies/load balancers)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Check for other proxy headers
    forwarded = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-By")
    if forwarded:
        return forwarded.strip()

    # Fall back to remote_addr
    return request.remote_addr

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number format (basic)"""
    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', phone)
    # Check if it's a valid length (10-15 digits)
    return 10 <= len(digits_only) <= 15

def generate_verification_code(length=6):
    """Generate a random verification code"""
    import secrets
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def format_coordinates(lat, lng, precision=4):
    """Format coordinates for display"""
    if lat is None or lng is None:
        return "Unknown"
    return f"{lat:.{precision}f}, {lng:.{precision}f}"

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return ""
    # Remove potentially dangerous characters
    return re.sub(r'[<>]', '', str(text))

def truncate_text(text, max_length=100):
    """Truncate text to maximum length"""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def format_timestamp(timestamp):
    """Format timestamp for display"""
    if not timestamp:
        return "Never"
    if isinstance(timestamp, str):
        return timestamp
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def calculate_distance_display(distance_km):
    """Format distance for user display"""
    if distance_km < 1:
        return f"{round(distance_km * 1000)} meters"
    else:
        return f"{round(distance_km, 1)} km"</content>
<parameter name="filePath">/Users/robertlober/Documents/Deploy to Render/utils.py