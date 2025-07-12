import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

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
        subject = "Your OTP Code for VidHunt App"
        body = f"""
        Hi {name},<br><br>
        Your OTP code is: <b>{otp_code}</b><br><br>
        Please enter this code to verify your account.<br><br>
        If you did not register, please ignore this email.
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
