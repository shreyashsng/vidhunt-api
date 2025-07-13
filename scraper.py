from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from config import SCRAPE_TIMEOUT, PAGE_GOTO_TIMEOUT
import os
from datetime import datetime

def scrape_m3u8_url(page_url):
    print(f"🚀 [SCRAPER] Starting scrape for URL: {page_url}")
    print(f"⏰ [SCRAPER] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    with sync_playwright() as p:
        print(f"🔧 [SCRAPER] Launching Chromium browser...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            java_script_enabled=True
        )
        page = context.new_page()
        print(f"✅ [SCRAPER] Browser launched successfully")

        # ⛔️ Block unnecessary resources
        def block_resources(route, request):
            if request.resource_type in ["image", "stylesheet", "font"]:
                print(f"🚫 [SCRAPER] Blocked {request.resource_type}: {request.url[:100]}...")
                return route.abort()
            print(f"➡️ [SCRAPER] Allowing {request.resource_type}: {request.url[:100]}...")
            route.continue_()

        page.route("**/*", block_resources)

        # ✅ Go to the page
        try:
            print(f"🌐 [SCRAPER] Navigating to page with timeout {PAGE_GOTO_TIMEOUT}ms...")
            page.goto(page_url, timeout=PAGE_GOTO_TIMEOUT)
            print(f"✅ [SCRAPER] Page loaded successfully")
        except Exception as e:
            print(f"❌ [SCRAPER] Page load error: {e}")
            browser.close()
            return None

        m3u8_url = None

        try:
            print(f"🔍 [SCRAPER] Waiting for .m3u8 response with timeout {SCRAPE_TIMEOUT}s...")
            with page.expect_response(lambda res: ".m3u8" in res.url, timeout=SCRAPE_TIMEOUT * 1000) as resp_info:
                pass  # Wait for it
            response = resp_info.value
            m3u8_url = response.url
            print(f"🎉 [SCRAPER] Found .m3u8 URL: {m3u8_url}")
        except PlaywrightTimeout:
            print(f"⚠️ [SCRAPER] Timed out waiting for .m3u8 response after {SCRAPE_TIMEOUT}s")
        except Exception as e:
            print(f"❌ [SCRAPER] Error waiting for .m3u8 response: {e}")

        print(f"🔒 [SCRAPER] Closing browser...")
        browser.close()
        
        if m3u8_url:
            print(f"✅ [SCRAPER] Scrape completed successfully: {m3u8_url}")
        else:
            print(f"❌ [SCRAPER] Scrape completed but no .m3u8 URL found")
            
        return m3u8_url
