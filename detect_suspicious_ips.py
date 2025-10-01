import pandas as pd
import smtplib
from email.mime.text import MIMEText

# Load Wireshark exported CSV file
csv_file = "D:\FolderName\Network_traffic.csv"
# full path to your CSV
df = pd.read_csv(csv_file)

print("Columns in CSV:", df.columns)  # Debug: check column names

# Adjust this if your source IP column has a different name
source_ip_column = 'Source'

# Example: Detect IPs with more than 500 packets sent (adjust threshold)
threshold_packets = 500

# Count packets per source IP
ip_packet_counts = df[source_ip_column].value_counts()

# Filter suspicious IPs
suspicious_ips = ip_packet_counts[ip_packet_counts > threshold_packets]

if suspicious_ips.empty:
    print("No suspicious IPs detected.")
else:
    print("Suspicious IPs detected:")
    print(suspicious_ips)

    # Prepare alert email
    sender = 'amruthasureshmanjula@gmail.com'  # Your Gmail address
    receiver = 'principal@rljit.in'      # RLJIT admin email
    subject = 'Alert: Suspicious IPs Detected on rljit.in'

    body = "Dear RLJIT Admin,\n\nThe following IP addresses have been detected sending unusually high traffic during the recent test:\n\n"
    for ip, count in suspicious_ips.items():
        body += f"- {ip}: {count} packets\n"
    body += "\nPlease investigate these IPs.\n\nRegards,\nAutomated Detection System"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = receiver

    # Send email via Gmail SMTP
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = "amruthasureshmanjula@gmail.com"
    smtp_password = 'rkqc sqbg mnxo tqpc'  # Use app password if 2FA enabled

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(sender, receiver, msg.as_string())
        print("Alert email sent to RLJIT admin.")
    except Exception as e:
        print(f"Failed to send alert email: {e}")
