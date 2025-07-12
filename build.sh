#!/bin/bash
set -e

echo "=== Installing Python packages ==="
pip install --upgrade pip
pip install -r requirements.txt

echo "=== Setting up Playwright browsers ==="
export PLAYWRIGHT_BROWSERS_PATH=/tmp/playwright
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0

# Install chromium browser without system dependencies (no --with-deps)
playwright install chromium

echo "=== Build completed successfully ==="
