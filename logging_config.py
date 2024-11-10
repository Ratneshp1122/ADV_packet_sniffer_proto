import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set up logging configuration
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Log to console
            logging.FileHandler("attack_log.txt")  # Log to file
        ]
    )

# Function to log anomalies to a separate file
def log_anomaly(message):
    # Get or create the 'anomaly_logger'
    logger = logging.getLogger("anomaly_logger")
    if not logger.hasHandlers():
        file_handler = logging.FileHandler("anomaly_log.log")
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.info(message)

# Function to log attacks or events
def log_attack(message):
    # Get or create the 'attack_logger'
    logger = logging.getLogger("attack_logger")
    if not logger.hasHandlers():
        file_handler = logging.FileHandler("attack_log.log")
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.info(message)

# Function to send email alerts when an attack is detected
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
        server = smtplib.SMTP("smtp.example.com", 587)  # Use the appropriate SMTP server
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.close()
        logging.info("Alert sent via email.")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

# Ensure logging is set up when the module is imported
setup_logging()
