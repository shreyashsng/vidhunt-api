FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ⬅️ Install browsers (Chromium, WebKit, Firefox)
RUN playwright install --with-deps

# (Optional) Verify Playwright installation
RUN python -c "from playwright.sync_api import sync_playwright; print('Playwright installed successfully')"

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Start the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "120", "app:app"]
