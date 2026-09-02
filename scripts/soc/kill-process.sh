#!/bin/bash
# Wazuh Active Response - Manager-side alerter
# Location: /var/ossec/active-response/bin/kill-process.sh
# Runs on: server
# Triggered by: rules 100010-100021

LOG=/var/ossec/logs/active-responses.log
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TMPJSON=$(mktemp /tmp/wazuh_ar_XXXXXX.json)
TMPVARS=$(mktemp /tmp/wazuh_vars_XXXXXX.sh)

# Capture stdin
dd bs=65536 count=1 > "$TMPJSON" 2>/dev/null

# Parse all fields in one Python call writing to vars file
python3 - << PYEOF >> "$TMPVARS" 2>> "$LOG"
import json, sys

try:
    with open('$TMPJSON', 'rb') as f:
        raw = f.read()
    d = json.loads(raw)
    a = d['parameters']['alert']
    ed = a.get('data', {}).get('win', {}).get('eventdata', {})

    def safe(v):
        return str(v).replace("'", "'\\''").replace('\n', ' ').replace('\r', '')

    print("RULE_ID='" + safe(a.get('rule', {}).get('id', 'N/A')) + "'")
    print("RULE_DESC='" + safe(a.get('rule', {}).get('description', 'N/A')) + "'")
    print("AGENT='" + safe(a.get('agent', {}).get('name', 'N/A')) + "'")
    print("AGENT_IP='" + safe(a.get('agent', {}).get('ip', 'N/A')) + "'")
    print("PROC_IMAGE='" + safe(ed.get('image', 'N/A')) + "'")
    print("PROC_CMD='" + safe(ed.get('commandLine', 'N/A')) + "'")
    print("PROC_PID='" + safe(ed.get('processId', 'N/A')) + "'")
    print("PROC_USER='" + safe(ed.get('user', 'N/A')) + "'")
    print("PARENT='" + safe(ed.get('parentImage', 'N/A')) + "'")
except Exception as e:
    sys.stderr.write('[PARSE_ERROR] ' + str(e) + '\n')
    for var in ['RULE_ID','RULE_DESC','AGENT','AGENT_IP','PROC_IMAGE','PROC_CMD','PROC_PID','PROC_USER','PARENT']:
        print(var + "='N/A'")
PYEOF

source "$TMPVARS"
rm -f "$TMPJSON" "$TMPVARS"

echo "[$TIMESTAMP] Rule $RULE_ID fired on $AGENT ($AGENT_IP) - $RULE_DESC" >> "$LOG"

KILL_RULES="100013 100014 100015 100016 100017"
ACTION="Alert only - no process kill for this rule type."
for r in $KILL_RULES; do
    if [ "$RULE_ID" = "$r" ]; then
        ACTION="Process termination dispatched to agent."
        break
    fi
done

# Process and context detail is written directly to the active-response
# log rather than emailed. Native Wazuh email notifications already
# cover these rule IDs (email_alert_level in ossec.conf), so a second,
# custom email here would only duplicate that.
echo "[$TIMESTAMP] Rule Details:" >> "$LOG"
echo "  Description : $RULE_DESC" >> "$LOG"
echo "  Agent       : $AGENT ($AGENT_IP)" >> "$LOG"
echo "  Image       : $PROC_IMAGE" >> "$LOG"
echo "  PID         : $PROC_PID" >> "$LOG"
echo "  User        : $PROC_USER" >> "$LOG"
echo "  CmdLine     : $PROC_CMD" >> "$LOG"
echo "  Parent      : $PARENT" >> "$LOG"
echo "  Action      : $ACTION" >> "$LOG"

exit 0