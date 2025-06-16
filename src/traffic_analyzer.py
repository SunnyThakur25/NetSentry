import pyshark
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("data/logs/netsentry.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def analyze_traffic(interface: str, duration: int = 10) -> List[Dict[str, Any]]:
    """Analyze traffic for camera streams using pyshark."""
    camera_streams = []
    
    try:
        logger.info(f"Analyzing traffic on {interface} for {duration} seconds...")
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="rtsp or (http and tcp.port == 80 and http.request.method == GET)"
        )
        
        capture.sniff(timeout=duration)
        for packet in capture:
            try:
                if "rtsp" in packet or ("http" in packet and "MJPEG" in str(packet)):
                    stream = {
                        "src_ip": packet.ip.src,
                        "dst_ip": packet.ip.dst,
                        "protocol": packet.highest_layer,
                        "timestamp": packet.sniff_time.isoformat()
                    }
                    camera_streams.append(stream)
            except AttributeError:
                logger.debug(f"Skipping malformed packet: {packet}")
        
        logger.info(f"Found {len(camera_streams)} potential camera streams")
        return camera_streams
    
    except Exception as e:
        logger.error(f"Traffic analysis failed: {str(e)}")
        return []