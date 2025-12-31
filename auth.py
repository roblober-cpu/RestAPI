"""
Authentication module for the visitor tracking application.
Handles password hashing, geographic authentication, and user verification.
"""

import hashlib
import secrets
from math import radians, sin, cos, sqrt, atan2
from .database import db_get_system_config, db_get_user_by_email, db_check_user_exists

def hash_password(password):
    """Hash password with salt using SHA-256"""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(stored_hash, password):
    """Verify password against stored hash"""
    try:
        salt, hashed = stored_hash.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == hashed
    except:
        return False

def calculate_distance(lat1, lng1, lat2, lng2):
    """Calculate the great circle distance between two points on Earth using the haversine formula"""
    # Convert latitude and longitude from degrees to radians
    lat1_rad = radians(lat1)
    lng1_rad = radians(lng1)
    lat2_rad = radians(lat2)
    lng2_rad = radians(lng2)

    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlng = lng2_rad - lng1_rad

    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlng / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    # Earth's radius in kilometers
    R = 6371.0

    # Calculate the distance
    distance = R * c

    return distance

def validate_geographic_challenge(challenge_key, clicked_lat, clicked_lng):
    """Validate a geographic challenge on the server side"""
    config = db_get_system_config(challenge_key)
    if not config:
        return False, "Challenge not found"

    # Calculate distance
    correct_lat = config['lat']
    correct_lng = config['lng']
    tolerance = config.get('tolerance_meters', 20.0) / 1000.0  # Convert to kilometers

    distance = calculate_distance(float(clicked_lat), float(clicked_lng), correct_lat, correct_lng)

    if distance <= tolerance:
        return True, f"Successfully authenticated to {config['name']}!"
    else:
        return False, f"Incorrect location. {round(distance * 1000)} meters away from {config['name']}."

def authenticate_user(email, password):
    """Authenticate a user with email and password"""
    user = db_get_user_by_email(email)
    if not user:
        return False, "User not found"

    if verify_password(user['password_hash'], password):
        return True, user
    else:
        return False, "Invalid password"

def check_user_registration_eligibility(email):
    """Check if a user can register with this email"""
    exists = db_check_user_exists(email)
    return not exists, "Email already registered" if exists else None</content>
<parameter name="filePath">/Users/robertlober/Documents/Deploy to Render/auth.py