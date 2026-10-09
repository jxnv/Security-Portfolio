# Title: Tap Driver Installation
# ID: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
# Status: test
# Level: medium
# Author: Daniil Yugoslavskiy, Ian Davis, oscd.community
# Date: 2019-10-24
# Tags: attack.exfiltration, attack.t1048
# Description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Tap Driver Installation
def rule(event):
    # Detection Logic:
    # (Provider_Name="Service Control Manager" AND EventID="7045" AND ImagePath="*tap0901*")
    return True

def title(event):
    return "Tap Driver Installation"

