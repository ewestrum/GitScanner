#!/usr/bin/env python3
"""Test email configuration"""

import os
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from config_manager import ConfigManager

def test_email_config():
    print("🔍 Testing email configuration...")
    
    try:
        # Load config
        config_manager = ConfigManager('.env')
        config = config_manager.config_data
        
        print(f"📋 Email Configuration:")
        print(f"   - Email Enabled: {config.get('EMAIL_ENABLED')}")
        print(f"   - SMTP Server: {config.get('SMTP_SERVER')}")
        print(f"   - SMTP Port: {config.get('SMTP_PORT')}")
        print(f"   - Sender Email: {config.get('SENDER_EMAIL')}")
        print(f"   - Sender Password: {'*' * len(config.get('SENDER_PASSWORD', '')) if config.get('SENDER_PASSWORD') else 'NOT SET'}")
        print(f"   - Recipients: {config.get('RECIPIENT_EMAILS')}")
        
        # Test SMTP connection
        if config.get('EMAIL_ENABLED') is True:
            print(f"\n🧪 Testing SMTP connection...")
            
            smtp_server = config.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(config.get('SMTP_PORT', 587))
            sender_email = config.get('SENDER_EMAIL')
            sender_password = config.get('SENDER_PASSWORD')
            
            if not sender_email or not sender_password:
                print("❌ Email credentials not configured")
                return
            
            try:
                # Create SMTP connection
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                
                print(f"   ✅ Connected to {smtp_server}:{smtp_port}")
                
                # Test login
                server.login(sender_email, sender_password)
                print(f"   ✅ Authentication successful for {sender_email}")
                
                # Send test email
                recipient_emails = config.get('RECIPIENT_EMAILS', [])
                if isinstance(recipient_emails, str):
                    recipient_emails = [email.strip() for email in recipient_emails.split(',') if email.strip()]
                elif not isinstance(recipient_emails, list):
                    recipient_emails = []
                
                if recipient_emails:
                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = ', '.join(recipient_emails)
                    msg['Subject'] = "GitHub Monitor Test Email"
                    
                    body = """
This is a test email from GitHub Monitor to verify email configuration.

If you receive this email, your email notification system is working correctly!

Timestamp: {timestamp}
                    """.format(timestamp=str(config_manager))
                    
                    msg.attach(MIMEText(body, 'plain'))
                    
                    server.send_message(msg)
                    print(f"   ✅ Test email sent to: {', '.join(recipient_emails)}")
                else:
                    print("   ⚠️  No recipient emails configured")
                
                server.quit()
                print(f"\n🎉 Email test completed successfully!")
                
            except smtplib.SMTPAuthenticationError as e:
                print(f"   ❌ Authentication failed: {e}")
                print("   💡 For Gmail, make sure you're using an App Password, not your regular password")
                print("   💡 Create App Password at: https://myaccount.google.com/apppasswords")
            except Exception as e:
                print(f"   ❌ SMTP error: {e}")
        else:
            print("   ⚠️  Email notifications are disabled")
        
    except Exception as e:
        print(f"❌ Error during email test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_email_config()