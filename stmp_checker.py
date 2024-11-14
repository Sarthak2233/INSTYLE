import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, body, recipient, sender_email, sender_password):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    text = msg.as_string()
    server.sendmail(sender_email, recipient, text)
    server.quit()

# Replace these with your actual email and password
sender_email = "sarakbasnet6@gmail.com"
sender_password = "sarakbasnet6!@#"

subject = "Test Subject"
body = "This is a test email."
recipient = "sarthak.basnet5@gmail.com"

send_email(subject, body, recipient, sender_email, sender_password)

