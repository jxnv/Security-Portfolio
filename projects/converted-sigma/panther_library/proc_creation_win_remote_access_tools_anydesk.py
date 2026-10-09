# Title: Remote Access Tool - AnyDesk Execution
# ID: b52e84a3-029e-4529-b09b-71d19dd27e94
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-02-11
# Tags: attack.command-and-control, attack.t1219.002
# Description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
# These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
# Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Access Tool - AnyDesk Execution
def rule(event):
    # Detection Logic:
    # (((Image="*\\AnyDesk.exe" OR Image="*\\AnyDeskMSI.exe")) OR (Description="AnyDesk") OR (Product="AnyDesk") OR (Company="AnyDesk Software GmbH"))
    return True

def title(event):
    return "Remote Access Tool - AnyDesk Execution"

