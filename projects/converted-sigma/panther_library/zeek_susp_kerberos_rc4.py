# Title: Kerberos Network Traffic RC4 Ticket Encryption
# ID: 503fe26e-b5f2-4944-a126-eab405cc06e5
# Status: test
# Level: medium
# Author: sigma
# Date: 2020-02-12
# Tags: attack.credential-access, attack.t1558.003
# Description: Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Kerberos Network Traffic RC4 Ticket Encryption
def rule(event):
    # Detection Logic:
    # ((request_type="TGS" AND cipher="rc4-hmac") AND NOT ((service="$*")))
    return True

def title(event):
    return "Kerberos Network Traffic RC4 Ticket Encryption"

