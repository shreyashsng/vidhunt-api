from playwright.sync_api import sync_playwright

playwright = sync_playwright().start()
browser = playwright.chromium.launch(headless=True)
context = browser.new_context(
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    java_script_enabled=True,
)

# ⛔️ Block unnecessary resources globally
def block_resources(route, request):
    if request.resource_type in ["image", "stylesheet", "font"]:
        return route.abort()
    route.continue_()

context.route("**/*", block_resources)

def get_context():
    return context

def close_browser():
    context.close()
    browser.close()
    playwright.stop()
