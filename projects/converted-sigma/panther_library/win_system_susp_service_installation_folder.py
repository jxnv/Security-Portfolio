# Title: Service Installation in Suspicious Folder
# ID: 5e993621-67d4-488a-b9ae-b420d08b96cb
# Status: test
# Level: medium
# Author: pH-T (Nextron Systems)
# Date: 2022-03-18
# Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
# Description: Detects service installation in suspicious folder appdata
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service Installation in Suspicious Folder
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045" AND (ImagePath="*\\AppData\\*" OR ImagePath="*\\\\\\\\127.0.0.1*" OR ImagePath="*\\\\\\\\localhost*")) AND NOT ((ServiceName="Zoom Sharing Service" AND ImagePath="*:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe*")))
    return True

def title(event):
    return "Service Installation in Suspicious Folder"

