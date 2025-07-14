import requests
import uuid
from typing import Dict, Optional, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_ip_and_location_data() -> Tuple[str, Dict[str, Optional[str]]]:
    """
    Get both IP address and location data in a single API call to ipapi.co
    """
    try:
        response = requests.get("https://ipapi.co/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        ip_address = data.get("ip", "127.0.0.1")
        location_data = {
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude")
        }
        
        logger.info(f"Successfully retrieved location data: IP={ip_address}, Country={location_data['country']}")
        return ip_address, location_data
        
    except requests.RequestException as e:
        logger.error(f"Error fetching data from ipapi.co: {e}")
        return "127.0.0.1", {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }
    except Exception as e:
        logger.error(f"Unexpected error getting IP and location data: {e}")
        return "127.0.0.1", {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }

def get_device_id_from_request(request) -> str:
    """
    Extract device ID from request cookies or headers
    Device ID should be generated on frontend and sent via cookie/header
    """
    # Try to get device ID from cookie first
    device_id = request.cookies.get("device_id")
    
    # If not in cookie, try custom header
    if not device_id:
        device_id = request.headers.get("X-Device-ID")
    
    # If still not found, return a default/unknown identifier
    if not device_id:
        logger.warning("No device ID found in request")
        return "unknown_device"
    
    return device_id

def calculate_derived_columns(request) -> Dict:
    """
    Calculate all derived columns for a transaction
    """
    # Get device ID from request (generated on frontend)
    device_id = get_device_id_from_request(request)
    
    # Get IP and location data in a single call
    ip_address, location_data = get_ip_and_location_data()
    
    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "country": location_data["country"],
        "city": location_data["city"],
        "latitude": location_data["latitude"],
        "longitude": location_data["longitude"],
        "initiation_mode": "Default"  # Always set to Default as requested
    }