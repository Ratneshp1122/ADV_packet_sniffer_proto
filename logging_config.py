import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("attack_log.txt")  
        ]
    )

def log_anomaly(message):
    logger = logging.getLogger("anomaly_logger")
    if not logger.hasHandlers():
        file_handler = logging.FileHandler("anomaly_log.log")
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.info(message)

def log_attack(message):
    logger = logging.getLogger("attack_logger")
    if not logger.hasHandlers():
        file_handler = logging.FileHandler("attack_log.log")
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.info(message)

def send_email_alert(subject, body):
    sender_email = "your_email@example.com"
    receiver_email = "receiver_email@example.com"
    password = "your_email_password"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.example.com", 587)  
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.close()
        logging.info("Alert sent via email.")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

setup_logging()
