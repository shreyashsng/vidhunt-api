from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from utils import send_otp_email
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from authlib.jose import jwt as authlib_jwt, JoseError
import time
from datetime import timedelta
import os, secrets

from database import get_all_users, PLAN_LIMITS

from flask import g 
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash
from database import (
    get_m3u8_url, save_url, get_all_cached_urls,
    create_user, get_user_by_username, authenticate_user, is_valid_api_key, get_user_by_id, regenerate_api_key, check_and_increment_rate_limit
)
from werkzeug.security import generate_password_hash, check_password_hash
from scraper import scrape_m3u8_url
from config import SCRAPE_BASE_URL
from concurrent.futures import ThreadPoolExecutor, as_completed

routes = Blueprint("routes", __name__)

# Initialize JWT
def init_jwt(app):
    jwt_secret = os.environ.get("JWT_SECRET_KEY", None)
    if not jwt_secret:
        jwt_secret = secrets.token_hex(32)
        print("[WARNING] Using a generated JWT secret key. Set JWT_SECRET_KEY in production!")
    app.config["JWT_SECRET_KEY"] = jwt_secret
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
    JWTManager(app)

# Authlib JWT (HWT) utility functions
def encode_authlib_jwt(user):
    jwt_secret = os.environ.get("JWT_SECRET_KEY", "changeme")
    header = {"alg": "HS256"}
    payload = {
        "sub": user["id"],
        "username": user.get("username", user.get("name")),
        "isAdmin": user["is_admin"],
        "exp": int(time.time()) + 86400  # 1 day expiry
    }
    return authlib_jwt.encode(header, payload, jwt_secret).decode()

def decode_authlib_jwt(token):
    jwt_secret = os.environ.get("JWT_SECRET_KEY", "changeme")
    try:
        claims = authlib_jwt.decode(token, jwt_secret)
        claims.validate()
        return claims
    except JoseError as e:
        return None

# Middleware to check API key

def require_api_key():
    api_key = request.args.get("api_key")
    if not api_key or not is_valid_api_key(api_key):
        return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
    return None

@routes.route("/", methods=["GET", "POST"])
def index():
    user = None
    is_admin = False
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        is_admin = user["is_admin"] if user else False
    return render_template("index.html", username=user["name"] if user else None, is_admin=is_admin)


import random
from datetime import datetime, timedelta
from database import get_db_connection




@routes.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Support both form and JSON
        if request.is_json:
            data = request.get_json()
            name = data.get("name")
            email = data.get("email")
            password = data.get("password")
        else:
            name = request.form.get("name")
            email = request.form.get("email")
            password = request.form.get("password")
        if not name or not email or not password:
            msg = "All fields are required."
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 400
            flash(msg, "error")
            return render_template("register.html")
        from database import get_user_by_email, create_user
        if get_user_by_email(email):
            msg = "Email already exists"
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 409
            flash(msg, "error")
            return render_template("register.html")
        otp_code = f"{random.randint(100000, 999999)}"
        otp_expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        user_data = {
            "name": name,
            "email": email,
            "otp_code": otp_code,
            "otp_expires_at": otp_expires_at
        }
        
        try:
            create_user(user_data, password)
        except ValueError as e:
            msg = str(e)
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 409
            flash(msg, "error")
            return render_template("register.html")
        except Exception as e:
            msg = "Registration failed. Please try again."
            print(f"[ERROR] User creation failed: {e}")
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 500
            flash(msg, "error")
            return render_template("register.html")
            
        # Send OTP to email using Gmail SMTP
        from utils import send_otp_email
        try:
            send_otp_email(email, name, otp_code)
        except Exception as e:
            print(f"[WARNING] Could not send OTP email: {e}")
        if request.is_json:
            return jsonify({"status": "success", "message": "Registered. Please verify OTP.", "email": email}), 201
        # Show OTP on next page
        return redirect(url_for("routes.verify_otp", email=email))
    return render_template("register.html")

# OTP verification route (supports HTML and JSON, uses email)
@routes.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            otp_code = data.get("otp_code")
        else:
            email = request.form.get("email")
            otp_code = request.form.get("otp_code")
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user and user["otp_code"] == otp_code:
            if datetime.utcnow() <= datetime.fromisoformat(user["otp_expires_at"]):
                cur.execute("UPDATE users SET is_verified = 1, otp_code = NULL, otp_expires_at = NULL WHERE email = %s", (email,))
                conn.commit()
                conn.close()
                msg = "Verification successful! You can now log in."
                if request.is_json:
                    return jsonify({"status": "success", "message": msg, "verified": True}), 200
                flash(msg, "success")
                return redirect(url_for("routes.login"))
            else:
                msg = "OTP expired. Please register again."
                if request.is_json:
                    return jsonify({"status": "error", "message": msg, "verified": False}), 400
                flash(msg, "danger")
        else:
            msg = "Invalid OTP."
            if request.is_json:
                return jsonify({"status": "error", "message": msg, "verified": False}), 400
            flash(msg, "danger")
        conn.close()
        if not request.is_json:
            return render_template("verify_otp.html", email=email)
    email = request.form.get("email") if request.method == "POST" else request.args.get("email")
    return render_template("verify_otp.html", email=email)






@routes.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Support both form and JSON
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            password = data.get("password")
        else:
            email = request.form["email"]
            password = request.form["password"]
        from database import get_user_by_email
        user = get_user_by_email(email)
        from werkzeug.security import check_password_hash
        if user and check_password_hash(user["password_hash"], password):
            if not user["is_verified"]:
                msg = "Please verify your account using OTP before logging in."
                if request.is_json:
                    return jsonify({"status": "error", "message": msg, "need_verification": True}), 403
                flash(msg, "error")
                return redirect(url_for("routes.verify_otp", email=email))
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["name"]
            if request.is_json:
                return jsonify({"status": "success", "message": "Login successful.", "isAdmin": user["is_admin"]}), 200
            flash("Login successful.", "success")
            if user["is_admin"]:
                return redirect(url_for("routes.admin_panel"))
            else:
                return redirect(url_for("routes.dashboard"))
        else:
            msg = "Invalid credentials."
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 401
            flash(msg, "danger")
            return redirect(url_for("routes.login"))
    # Add forgot password link
    return render_template("login.html", forgot_password_url=url_for("routes.forgot_password"))


# Dashboard route
@routes.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("routes.login"))
    user = get_user_by_id(session["user_id"])
    from database import PLAN_LIMITS
    plan = user["plan"]
    requests_today = user["requests_today"]
    plan_limit = PLAN_LIMITS.get(plan, 100)
    return render_template(
        "dashboard.html",
        username=user["name"],
        api_key=user["api_key"],
        plan=plan,
        requests_today=requests_today,
        plan_limit=plan_limit
    )

@routes.route("/logout")
def logout():
    session.clear()  # Clears all session data (user_id, etc.)
    return redirect(url_for("routes.login"))  # Redirect to login page


@routes.route("/api/movie/<tmdb_id>")
def api_movie(tmdb_id):
    # Allow API key, Flask-JWT-Extended, or Authlib JWT
    user = None
    api_key = request.args.get("api_key")
    if api_key:
        if not is_valid_api_key(api_key):
            return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE api_key = %s", (api_key,))
        user = cur.fetchone()
        conn.close()
    else:
        # Try Flask-JWT-Extended first
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        try:
            verify_jwt_in_request()
            identity = get_jwt_identity()
            user = get_user_by_id(identity["id"])
        except Exception:
            # Try Authlib JWT (from Authorization: Bearer ...)
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]
                claims = decode_authlib_jwt(token)
                if claims:
                    user = get_user_by_id(claims["sub"])
                else:
                    return jsonify({"status": "error", "message": "Invalid or expired Authlib JWT"}), 401
            else:
                return jsonify({"status": "error", "message": "Missing authentication"}), 401

    # Require verified user for API access
    if not user or not user["is_verified"]:
        return jsonify({"status": "error", "message": "Account not verified. Please complete OTP verification."}), 403

    # Rate limiting
    allowed, plan_limit = check_and_increment_rate_limit(user)
    if not allowed:
        return jsonify({
            "status": "error",
            "message": f"You have reached your daily quota for the '{user['plan']}' plan (limit: {plan_limit} requests per day). Please try again tomorrow or upgrade your plan.",
            "plan": user["plan"],
            "limit": plan_limit,
            "requests_today": user["requests_today"]
        }), 429

    if not tmdb_id.isdigit():
        return jsonify({"status": "error", "message": "Invalid TMDB ID"}), 400

    cached = get_m3u8_url(tmdb_id)
    if cached:
        return jsonify({"status": "cached", "tmdb_id": tmdb_id, "m3u8_url": cached}), 200

    try:
        url = f"{SCRAPE_BASE_URL}/movie/{tmdb_id}"
        m3u8 = scrape_m3u8_url(url)
        if m3u8:
            save_url(tmdb_id, m3u8)
            return jsonify({"status": "scraped", "tmdb_id": tmdb_id, "m3u8_url": m3u8}), 200
        else:
            return jsonify({"status": "error", "message": "No .m3u8 URL found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
# Admin: change user plan
@routes.route("/admin/change-plan", methods=["POST"])
def admin_change_plan():
    if "user_id" not in session:
        return redirect(url_for("routes.login"))
    user = get_user_by_id(session["user_id"])
    from database import PLAN_LIMITS
    if not user or not user["is_admin"]:
        return "Forbidden", 403
    target_user_id = request.form.get("user_id")
    new_plan = request.form.get("plan")
    if target_user_id and new_plan in PLAN_LIMITS:
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET plan = %s WHERE id = %s", (new_plan, target_user_id))
        conn.commit()
        conn.close()
        flash(f"Plan updated for user ID {target_user_id}", "success")
    return redirect(url_for("routes.admin_panel"))

@routes.route("/api/all", methods=["GET"])
def get_all_scraped_data():
    api_key = request.args.get("api_key")
    user = None
    if api_key:
        if not is_valid_api_key(api_key):
            return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE api_key = %s", (api_key,))
        user = cur.fetchone()
        conn.close()
    else:
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        try:
            verify_jwt_in_request()
            identity = get_jwt_identity()
            user = get_user_by_id(identity["id"])
        except Exception:
            # Try Authlib JWT (from Authorization: Bearer ...)
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]
                claims = decode_authlib_jwt(token)
                if claims:
                    user = get_user_by_id(claims["sub"])
                else:
                    return jsonify({"status": "error", "message": "Invalid or expired Authlib JWT"}), 401
            else:
                return jsonify({"status": "error", "message": "Missing authentication"}), 401

    try:
        data = get_all_cached_urls()
        return jsonify({"status": "success", "data": data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@routes.route("/api/health")
def health():
    return jsonify({"status": "ok", "message": "API is healthy"}), 200

@routes.route("/api/status")
def status():
    return jsonify({"status": "running", "version": "1.0.0"}), 200

@routes.route("/api/user/regenerate-key", methods=["POST"])
def api_regenerate_key():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    user_id = session["user_id"]
    new_key = regenerate_api_key(user_id)
    return jsonify({"status": "success", "api_key": new_key}), 200

# Admin endpoint to view and manage all users
@routes.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if "user_id" not in session:
        return redirect(url_for("routes.login"))
    user = get_user_by_id(session["user_id"])
    if not user or not user["is_admin"]:
        return "Forbidden", 403

    # Regenerate API key for a user (POST)
    if request.method == "POST":
        target_user_id = request.form.get("user_id")
        if target_user_id:
            new_key = regenerate_api_key(target_user_id)
            flash(f"API key regenerated for user ID {target_user_id}", "success")

    users = get_all_users() or []
    page = request.args.get("page", 1, type=int)
    per_page = 10
    total = len(users)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_users = users[start:end]
    total_pages = (total + per_page - 1) // per_page
    return render_template(
        "admin.html",
        users=paginated_users,
        plan_limits=PLAN_LIMITS,
        page=page,
        total_pages=total_pages
    )


# JWT login endpoint (returns token)
@routes.route("/api/token", methods=["POST"])
def api_token():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        access_token = create_access_token(identity={"id": user["id"], "username": user["name"], "isAdmin": user["is_admin"]})
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Bad username or password"}), 401

# Authlib JWT login endpoint (returns Authlib JWT)
@routes.route("/api/token_authlib", methods=["POST"])
def api_token_authlib():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        token = encode_authlib_jwt({"id": user["id"], "name": user["name"], "is_admin": user["is_admin"]})
        return jsonify(access_token=token, token_type="authlib"), 200
    return jsonify({"msg": "Bad username or password"}), 401

# Password reset token helpers
def generate_reset_token(email, secret=None):
    secret = secret or os.environ.get("FLASK_SECRET_KEY", "changeme")
    s = URLSafeTimedSerializer(secret)
    return s.dumps(email, salt="reset-password")

def confirm_reset_token(token, expiration=3600):
    secret = os.environ.get("FLASK_SECRET_KEY", "changeme")
    s = URLSafeTimedSerializer(secret)
    try:
        email = s.loads(token, salt="reset-password", max_age=expiration)
    except (SignatureExpired, BadSignature):
        return None
    return email
# Forgot password: request reset link
@routes.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        from database import get_user_by_email
        user = get_user_by_email(email)
        if not user:
            return render_template("forgot_password.html", error="No account with that email.")
        token = generate_reset_token(email)
        reset_url = url_for("routes.reset_password", token=token, _external=True, _scheme="http")
        try:
            send_otp_email(email, user["name"], otp_code=None, is_reset=True, reset_url=reset_url)
        except Exception as e:
            print(f"[WARNING] Could not send reset email: {e}")
        return render_template("forgot_password.html", message="If your email exists, a reset link has been sent.")
    return render_template("forgot_password.html")

# Reset password: set new password
@routes.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") if request.method == "GET" else request.form.get("token")
    if not token:
        return render_template("reset_password.html", error="Missing or invalid reset link.")
    email = confirm_reset_token(token)
    if not email:
        return render_template("reset_password.html", error="Invalid or expired reset link.")
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if not password or password != confirm_password:
            return render_template("reset_password.html", error="Passwords do not match.", email=email)
        from werkzeug.security import generate_password_hash
        from database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (generate_password_hash(password), email))
        conn.commit()
        conn.close()
        flash("Password reset successful! Please log in.", "success")
        return redirect(url_for("routes.login"))
    return render_template("reset_password.html", email=email, token=token)

# Serve OpenAPI spec for frontend (after Blueprint definition)

@routes.route("/openapi.json")
def openapi_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "VidHunt API",
            "version": "1.0.0",
            "description": "API documentation for VidHunt"
        },
        "paths": {
            "/api/movie/{tmdb_id}": {
                "get": {
                    "summary": "Get movie info by TMDB ID",
                    "parameters": [
                        {
                            "name": "tmdb_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Movie info",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return jsonify(spec)

# Admin manual scrape by TMDB ID
@routes.route("/api/movie/manual", methods=["POST"])
def admin_scrape_tmdb():
    if "user_id" not in session:
        return redirect(url_for("routes.login"))
    user = get_user_by_id(session["user_id"])
    if not user or not user["is_admin"]:
        return "Forbidden", 403
    tmdb_id = request.form.get("tmdb_id")
    if not tmdb_id or not tmdb_id.isdigit():
        flash("Invalid TMDB ID.", "error")
        return redirect(url_for("routes.admin_panel"))
    # Check cache first
    cached = get_m3u8_url(tmdb_id)
    if cached:
        flash(f".m3u8 already cached for TMDB ID {tmdb_id}.", "info")
        return redirect(url_for("routes.admin_panel"))
    # Scrape and cache
    try:
        url = f"{SCRAPE_BASE_URL}/movie/{tmdb_id}"
        m3u8 = scrape_m3u8_url(url)
        if m3u8:
            save_url(tmdb_id, m3u8)
            flash(f"Scraped and cached .m3u8 for TMDB ID {tmdb_id}.", "success")
        else:
            flash("No .m3u8 URL found for this TMDB ID.", "error")
    except Exception as e:
        flash(f"Error scraping: {e}", "error")
    return redirect(url_for("routes.admin_panel"))

# Admin: view all cached TMDB IDs and m3u8 URLs
@routes.route("/admin/movies", methods=["GET"])
def admin_movies():
    if "user_id" not in session:
        return redirect(url_for("routes.login"))
    user = get_user_by_id(session["user_id"])
    if not user or not user["is_admin"]:
        return "Forbidden", 403

    page = request.args.get("page", 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as count FROM m3u8_cache")
    total_row = cur.fetchone()
    total = total_row["count"] if total_row else 0
    cur.execute(
        "SELECT tmdb_id, m3u8_url FROM m3u8_cache ORDER BY tmdb_id DESC LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    rows = cur.fetchall()
    conn.close()
    movies = [{"tmdb_id": row["tmdb_id"], "m3u8_url": row["m3u8_url"]} for row in rows]
    total_pages = (total + per_page - 1) // per_page
    return render_template(
        "admin_movies.html",
        movies=movies,
        page=page,
        total_pages=total_pages
    )


