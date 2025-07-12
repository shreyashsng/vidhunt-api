from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from config import SCRAPE_TIMEOUT, PAGE_GOTO_TIMEOUT
import os

def scrape_m3u8_url(page_url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            java_script_enabled=True
        )
        page = context.new_page()

        # ⛔️ Block unnecessary resources
        def block_resources(route, request):
            if request.resource_type in ["image", "stylesheet", "font"]:
                return route.abort()
            route.continue_()

        page.route("**/*", block_resources)

        # ✅ Go to the page
        try:
            page.goto(page_url, timeout=PAGE_GOTO_TIMEOUT)
        except Exception as e:
            print("❌ Page load error:", e)
            browser.close()
            return None

        m3u8_url = None

        try:
            with page.expect_response(lambda res: ".m3u8" in res.url, timeout=SCRAPE_TIMEOUT * 1000) as resp_info:
                pass  # Wait for it
            response = resp_info.value
            m3u8_url = response.url
        except PlaywrightTimeout:
            print("⚠️ Timed out waiting for .m3u8 response")

        browser.close()
        return m3u8_url
