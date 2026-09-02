#!/bin/bash
# Absolute paths for every external command - wazuh-execd invokes this
# script with a minimal environment/PATH that is not guaranteed to match
# an interactive shell, so bare command names ('python3', 'curl', 'ssh')
# can silently fail to be found and produce empty output rather than an
# error. Adjust these if your system installs them elsewhere (confirm
# with 'which curl python3 ssh sudo').
CURL=/usr/bin/curl
PYTHON3=/usr/bin/python3
SSH=/usr/bin/ssh

LOG=/var/ossec/logs/active-responses.log
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

INTRA_VM="administrator@10.8.0.9"
SSH_KEY="/var/ossec/.ssh/id_rsa"
WAZUH_API="https://localhost:55000"
WAZUH_USER="wazuh-wui"
WAZUH_PASS=$(cat /var/ossec/.wazuh_api_pass 2>>"$LOG")

if [ -z "$WAZUH_PASS" ]; then
    echo "[$TIMESTAMP] ERROR: could not read /var/ossec/.wazuh_api_pass (empty or unreadable)" >> "$LOG"
    exit 1
fi

# Get JWT token
AUTH_RESPONSE=$($CURL -s -u "$WAZUH_USER:$WAZUH_PASS" -k -X POST "$WAZUH_API/security/user/authenticate")
TOKEN=$(echo "$AUTH_RESPONSE" | $PYTHON3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>>"$LOG")

if [ -z "$TOKEN" ]; then
    echo "[$TIMESTAMP] ERROR: failed to obtain API token. Response: $AUTH_RESPONSE" >> "$LOG"
    exit 1
fi
echo "[$TIMESTAMP] Obtained API token successfully." >> "$LOG"

# Get all agent IPs
AGENTS_RESPONSE=$($CURL -s -k -X GET "$WAZUH_API/agents?limit=100&status=active,pending,never_connected,disconnected" \
    -H "Authorization: Bearer $TOKEN")
AGENT_IPS=$(echo "$AGENTS_RESPONSE" | $PYTHON3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for a in data.get('data', {}).get('affected_items', []):
        print(a.get('ip',''))
except Exception as e:
    sys.stderr.write('PARSE_ERROR: ' + str(e) + '\n')
" 2>>"$LOG")

if [ -z "$AGENT_IPS" ]; then
    echo "[$TIMESTAMP] WARNING: no agent IPs returned. Raw response: $AGENTS_RESPONSE" >> "$LOG"
else
    echo "[$TIMESTAMP] Retrieved agent IPs: $(echo "$AGENT_IPS" | tr '\n' ' ')" >> "$LOG"
fi

# Add each IP to UFW on blueTeamIntraVM
for IP in $AGENT_IPS; do
    if [ "$IP" != "127.0.0.1" ] && [ "$IP" != "10.8.0.9" ] && [ -n "$IP" ]; then
        SSH_OUTPUT=$($SSH -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$INTRA_VM" \
            "sudo ufw allow from $IP to any port 80,443 proto tcp" 2>&1)
        SSH_EXIT=$?
        if [ $SSH_EXIT -eq 0 ]; then
            echo "[$TIMESTAMP] Added $IP to UFW allowlist. Output: $SSH_OUTPUT" >> "$LOG"
        else
            echo "[$TIMESTAMP] ERROR: failed to add $IP (exit $SSH_EXIT). Output: $SSH_OUTPUT" >> "$LOG"
        fi
    fi
done

echo "[$TIMESTAMP] UFW sync complete" >> "$LOG"