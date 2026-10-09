# Title: Windows Defender Threat Detection Service Disabled
# ID: 6c0a7755-6d31-44fa-80e1-133e57752680
# Status: stable
# Level: medium
# Author: Ján Trenčanský, frack113
# Date: 2020-07-28
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects when the "Windows Defender Threat Protection" service is disabled.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Defender Threat Detection Service Disabled
def rule(event):
    # Detection Logic:
    # (EventID="7036" AND Provider_Name="Service Control Manager" AND (param1="Windows Defender Antivirus Service" OR param1="Service antivirus Microsoft Defender") AND (param2="stopped" OR param2="arrêté"))
    return True

def title(event):
    return "Windows Defender Threat Detection Service Disabled"

