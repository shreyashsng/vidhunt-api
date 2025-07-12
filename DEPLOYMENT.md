# Deployment Instructions for Render

## Python Version
- Uses Python 3.11.9 (specified in runtime.txt)
- Required for Playwright compatibility

## Environment Variables to Set in Render:

```
FLASK_SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
GMAIL_USER=your-gmail@gmail.com
GMAIL_PASS=your-app-specific-password
FROM_NAME=VidHunt App
BASE_URL=https://your-app-name.onrender.com
SCRAPE_BASE_URL=https://vidfast.pro
DATABASE_URL=your-neon-postgres-url
```

## Render Configuration:

- **Build Command:** `chmod +x build.sh && ./build.sh`
- **Start Command:** `gunicorn --bind :$PORT --workers 1 --timeout 120 --max-requests 1000 app:app`
- **Environment:** Python 3.11.9
- **Auto-Deploy:** Yes (recommended)

## Important Notes:

1. **Python 3.11.9 is required** - Playwright doesn't work with Python 3.13 yet
2. Build process installs Playwright and Chromium browser
3. Make sure your Neon database is accessible from Render's IP addresses
4. Update BASE_URL to your actual Render domain
5. Set all environment variables in Render's dashboard
6. The app will automatically detect production environment and enable secure cookies

## After Deployment:

1. Test the API endpoints
2. Verify admin panel access
3. Test user registration and login
4. Check email functionality (OTP sending)
5. Test movie scraping functionality (this should work with Playwright now)
