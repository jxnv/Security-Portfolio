# Title: Windows Defender Real-Time Protection Failure/Restart
# ID: dd80db93-6ec2-4f4c-a017-ad40da6ffe81
# Status: stable
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Christopher Peacock '@securepeacock' (Update)
# Date: 2023-03-28
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects issues with Windows Defender Real-Time Protection features
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Defender Real-Time Protection Failure/Restart
def rule(event):
    # Detection Logic:
    # (((EventID="3002" OR EventID="3007")) AND NOT ((Feature_Name="%%886" AND (Reason="%%892" OR Reason="%%858"))))
    return True

def title(event):
    return "Windows Defender Real-Time Protection Failure/Restart"

