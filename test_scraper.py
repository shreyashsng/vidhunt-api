#!/usr/bin/env python3
"""
Direct scraper test script
Tests if the scraper can fetch m3u8 URLs for specific TMDB IDs
"""

from scraper import scrape_m3u8_url
from config import SCRAPE_BASE_URL
import sys

def test_scraper_direct(tmdb_id):
    """Test scraper directly without API layers"""
    print(f"🧪 [TEST] Direct scraper test for TMDB ID: {tmdb_id}")
    print(f"🔧 [TEST] Base URL: {SCRAPE_BASE_URL}")
    
    # Construct the URL
    url = f"{SCRAPE_BASE_URL}/movie/{tmdb_id}"
    print(f"🌐 [TEST] Full URL: {url}")
    
    print(f"🚀 [TEST] Starting scrape...")
    print("=" * 60)
    
    try:
        # Call the scraper
        result = scrape_m3u8_url(url)
        
        print("=" * 60)
        if result:
            print(f"✅ [TEST] SUCCESS: Found m3u8 URL!")
            print(f"🎯 [TEST] Result: {result}")
            return True
        else:
            print(f"❌ [TEST] FAILED: No m3u8 URL found")
            print(f"💡 [TEST] This could mean:")
            print(f"   - The movie doesn't exist on {SCRAPE_BASE_URL}")
            print(f"   - The site is blocking automated requests")
            print(f"   - The movie doesn't have streaming sources")
            print(f"   - There's a timeout or network issue")
            return False
            
    except Exception as e:
        print("=" * 60)
        print(f"💥 [TEST] EXCEPTION: {e}")
        print(f"🔍 [TEST] Exception type: {type(e).__name__}")
        return False

if __name__ == "__main__":
    # Test with the provided TMDB ID
    tmdb_id = "1156593"
    
    print(f"🎬 [TEST] Testing scraper with TMDB ID: {tmdb_id}")
    print(f"📝 [TEST] This will test if vidsrc.to has this movie and can provide m3u8 streams")
    print()
    
    success = test_scraper_direct(tmdb_id)
    
    print()
    print("=" * 60)
    if success:
        print(f"🎉 [TEST] OVERALL RESULT: Scraper is working for TMDB ID {tmdb_id}")
    else:
        print(f"😞 [TEST] OVERALL RESULT: Scraper failed for TMDB ID {tmdb_id}")
        print(f"🔍 [TEST] Try testing with a popular movie like:")
        print(f"   - 550 (Fight Club)")
        print(f"   - 157336 (Interstellar)")
        print(f"   - 299536 (Avengers: Infinity War)")
    print("=" * 60)
