# Title: Disable Windows IIS HTTP Logging
# ID: e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e
# Status: test
# Level: high
# Author: frack113
# Date: 2022-01-09
# Tags: attack.defense-impairment, attack.t1685.001
# Description: Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Disable Windows IIS HTTP Logging
def rule(event):
    # Detection Logic:
    # (((CommandLine="*set*" AND CommandLine="*config*" AND CommandLine="*section:httplogging*" AND CommandLine="*dontLog:true*")) AND ((Image="*\\appcmd.exe") OR (OriginalFileName="appcmd.exe")))
    return True

def title(event):
    return "Disable Windows IIS HTTP Logging"

