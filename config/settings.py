import os

CHROMEDRIVER_LOC = os.getenv("CHROMEDRIVER_LOC")

SENDER_MAIL = os.getenv("SENDER_MAIL")
SENDER_MAIL_PASSWORD = os.getenv("SENDER_MAIL_PASSWORD")

RECEIVER_MAIL = os.getenv("RECEIVER_MAIL")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

USER_AGENT = "NeoSpyder/2.0 (Defensive Security Research)"
