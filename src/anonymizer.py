import requests
import random
import re
import logging
from typing import Dict, Optional

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

TOR_PROXY = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}

def get_free_proxy() -> Dict[str, str]:
    """Scrape free proxy list."""
    try:
        response = requests.get("https://free-proxy-list.net/", timeout=5)
        proxies = re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", response.text)
        proxy = random.choice(proxies)
        logger.info(f"Selected proxy: {proxy}")
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    except Exception as e:
        logger.warning(f"Failed to fetch proxy, using Tor: {str(e)}")
        return TOR_PROXY

def anonymized_request(url: str) -> Optional[requests.Response]:
    """Make anonymized HTTP request."""
    try:
        proxies = get_free_proxy()
        headers = {
            "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.36"
        }
        response = requests.get(url, proxies=proxies, headers=headers, timeout=5)
        logger.info(f"Successful request to {url}")
        return response
    except Exception as e:
        logger.error(f"Request failed: {str(e)}")
        return None