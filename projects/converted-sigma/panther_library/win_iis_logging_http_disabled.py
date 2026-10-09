# Title: HTTP Logging Disabled On IIS Server
# ID: e8ebd53a-30c2-45bd-81bb-74befba07bdb
# Status: test
# Level: high
# Author: frack113
# Date: 2024-10-06
# Tags: attack.persistence, attack.defense-impairment, attack.t1685.001, attack.t1505.004
# Description: Detects changes to of the IIS server configuration in order to disable HTTP logging for successful requests.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HTTP Logging Disabled On IIS Server
def rule(event):
    # Detection Logic:
    # (EventID="29" AND Configuration="/system.webServer/httpLogging/@dontLog" AND NewValue="true")
    return True

def title(event):
    return "HTTP Logging Disabled On IIS Server"

