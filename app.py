from flask import Flask
from routes import routes, init_jwt
import os
import secrets
from datetime import timedelta

app = Flask(__name__)
app.register_blueprint(routes)

# Configure Flask secret key
flask_secret = os.environ.get("FLASK_SECRET_KEY", None)
if not flask_secret:
    flask_secret = secrets.token_hex(32)
    print("[WARNING] Using a generated Flask secret key. Set FLASK_SECRET_KEY in production!")
app.secret_key = flask_secret

# Session configuration
app.permanent_session_lifetime = timedelta(days=7)
app.config["SESSION_COOKIE_NAME"] = "vidhunt_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Set secure cookies for production (HTTPS)
is_production = os.environ.get("RENDER", False) or os.environ.get("RAILWAY_ENVIRONMENT", False)
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# Initialize JWT
init_jwt(app)

if __name__ == "__main__":
    # For local development
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
