"""
Test script for impromptuindian.com live site.
Handles the access code gate page and optionally saves auth for reuse.

Usage:
  # First run: enter access code, saves session to access_auth.json
  python test_live_site.py

  # Later runs: reuse saved session (no code needed)
  python test_live_site.py --reuse

Set WEBSITE_ACCESS_TOKEN env var for the access code (never commit it).
"""
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

LIVE_URL = "https://impromptuindian.com"
ACCESS_CODE = os.environ.get("WEBSITE_ACCESS_TOKEN", "YOUR_ACCESS_CODE")
AUTH_FILE = Path(__file__).parent / "access_auth.json"


def test_with_access():
    """Open site, enter access code, save session."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        print("Opening:", LIVE_URL)
        page.goto(LIVE_URL, timeout=60000)

        # Wait for access gate (input or redirect)
        try:
            page.wait_for_selector("input[type='password']", timeout=5000)
            print("Access gate detected. Entering code...")
            page.fill("input[type='password']", ACCESS_CODE)
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")
            print("After access title:", page.title())
        except Exception as e:
            print("No access gate (or already unlocked):", e)

        # Save session so you don't need access code next time
        context.storage_state(path=str(AUTH_FILE))
        print(f"Session saved to {AUTH_FILE}")

        page.screenshot(path="after_access.png")
        browser.close()


def test_with_saved_auth():
    """Reuse saved session - no access code needed."""
    if not AUTH_FILE.exists():
        print(f"Run test_with_access() first to create {AUTH_FILE}")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(storage_state=str(AUTH_FILE))
        page = context.new_page()

        print("Opening:", LIVE_URL, "(using saved auth)")
        page.goto(LIVE_URL, timeout=60000)

        print("Title:", page.title())
        page.screenshot(path="homepage.png")

        browser.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--reuse":
        test_with_saved_auth()
    else:
        test_with_access()
