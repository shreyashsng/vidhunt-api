# config.py
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

SCRAPE_TIMEOUT = 10  # seconds
PAGE_GOTO_TIMEOUT = 10000  # milliseconds
DB_PATH = "m3u8_cache.db"

# Base URLs and endpoints
SCRAPE_BASE_URL = os.environ.get("SCRAPE_BASE_URL", "http://example.com")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
