#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install --with-deps chromium

# Start the application
exec gunicorn --bind :$PORT --workers 1 --timeout 120 --max-requests 1000 app:app
