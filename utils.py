import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from flask import jsonify

def send_otp_email(to_email, name, otp_code, is_reset=False, reset_url=None):
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USER = os.environ.get("GMAIL_USER")  # Your Gmail address
    SMTP_PASS = os.environ.get("GMAIL_PASS")  # App password (not your main Gmail password)
    FROM_EMAIL = SMTP_USER
    FROM_NAME = os.environ.get("FROM_NAME", "VidHuntAPI")

    if is_reset and reset_url:
        subject = "Reset your password for VidHunt App"
        body = f"""
        Hi {name},<br><br>
        You requested a password reset.<br><br>
        Click the link below to reset your password:<br>
        <a href='{reset_url}'>Reset Password</a><br><br>
        If you did not request this, please ignore this email.
        """
    else:
        subject = "🔐 VidHunt Account Verification Code"
        body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; color: white;">
                <h1 style="margin: 0; font-size: 24px;">🎯 VidHunt</h1>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">Your verification code is ready!</p>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; margin-top: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <h2 style="color: #333; margin-top: 0;">Hi {name}! 👋</h2>
                <p style="color: #666; line-height: 1.6;">Welcome to VidHunt! To complete your registration, please use the verification code below:</p>
                
                <div style="background: #f8f9fa; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                    <p style="margin: 0; color: #333; font-size: 14px;">Your verification code:</p>
                    <h1 style="margin: 10px 0; color: #667eea; font-size: 32px; letter-spacing: 5px; font-family: 'Courier New', monospace;">{otp_code}</h1>
                    <p style="margin: 0; color: #666; font-size: 12px;">This code expires in 10 minutes</p>
                </div>
                
                <p style="color: #666; line-height: 1.6;">Simply enter this code on the verification page to access your dashboard and start using our API!</p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
                <p style="color: #999; font-size: 12px; text-align: center;">
                    If you didn't create an account with VidHunt, please ignore this email.<br>
                    This code will expire automatically and your email will not be used.
                </p>
            </div>
        </div>
        """
    msg = MIMEMultipart()
    msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())

def safe_datetime_parse(dt_value):
    """
    Safely parse datetime from various formats
    Returns datetime object or None if parsing fails
    """
    if dt_value is None:
        return None
        
    if isinstance(dt_value, datetime):
        return dt_value
        
    if isinstance(dt_value, str):
        try:
            # Try ISO format first
            return datetime.fromisoformat(dt_value.replace('Z', '+00:00'))
        except ValueError:
            try:
                # Try common format
                return datetime.strptime(dt_value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    # Try date only
                    return datetime.strptime(dt_value, '%Y-%m-%d')
                except ValueError:
                    print(f"[WARNING] Could not parse datetime: {dt_value}")
                    return None
    
    # Handle other types (timestamp, etc.)
    try:
        return datetime.fromtimestamp(float(dt_value))
    except (ValueError, TypeError):
        print(f"[WARNING] Could not parse datetime: {dt_value}")
        return None

def format_datetime_for_display(dt_value):
    """
    Format datetime for display in templates
    """
    dt = safe_datetime_parse(dt_value)
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M')
    return '-'

def get_utc_now_iso():
    """
    Get current UTC time as ISO string
    """
    return datetime.utcnow().isoformat()

def api_response(data, status_code=200):
    """
    Standardized API response with timestamp
    """
    response_data = {
        "timestamp": get_utc_now_iso(),
        **data
    }
    return jsonify(response_data), status_code
