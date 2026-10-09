# Title: Rclone Config File Creation
# ID: 34986307-b7f4-49be-92f3-e7a4d01ac5db
# Status: test
# Level: medium
# Author: Aaron Greetham (@beardofbinary) - NCC Group
# Date: 2021-05-26
# Tags: attack.exfiltration, attack.t1567.002
# Description: Detects Rclone config files being created
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Rclone Config File Creation
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*:\\Users\\*" AND TargetFilename="*\\.config\\rclone\\*"))
    return True

def title(event):
    return "Rclone Config File Creation"

