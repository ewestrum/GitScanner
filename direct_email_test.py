#!/usr/bin/env python3
"""Send direct test email"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_direct_test():
    print("📧 Sending direct test email...")
    
    # Email configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "westrum@gmail.com"
    sender_password = "gzfr dcfn lypc kvye"
    recipient_email = "westrum@gmail.com"
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"GitHub Monitor Direct Test - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        body = f"""
🔍 GitHub Monitor Email Test

This is a direct test email sent at {datetime.now()}.

This email confirms that:
✅ SMTP connection is working
✅ Gmail authentication is successful  
✅ Email delivery is functional

If you receive this email, your GitHub Monitor email notifications should be working correctly.

---
GitHub Monitor Enhanced Version
Test sent from: {sender_email}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        print(f"   Connecting to {smtp_server}:{smtp_port}...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        
        print(f"   Authenticating as {sender_email}...")
        server.login(sender_email, sender_password)
        
        print(f"   Sending email to {recipient_email}...")
        server.send_message(msg)
        server.quit()
        
        print(f"   ✅ Direct test email sent successfully!")
        print(f"   📬 Check your inbox at {recipient_email}")
        print(f"   📂 Also check your spam/junk folder if needed")
        
    except Exception as e:
        print(f"   ❌ Error sending direct test email: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    send_direct_test()