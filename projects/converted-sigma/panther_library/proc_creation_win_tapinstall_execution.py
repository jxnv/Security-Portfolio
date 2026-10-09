# Title: Tap Installer Execution
# ID: 99793437-3e16-439b-be0f-078782cf953d
# Status: test
# Level: medium
# Author: Daniil Yugoslavskiy, Ian Davis, oscd.community
# Date: 2019-10-24
# Tags: attack.exfiltration, attack.t1048
# Description: Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Tap Installer Execution
def rule(event):
    # Detection Logic:
    # ((Image="*\\tapinstall.exe") AND NOT ((((Image="*:\\Program Files\\Avast Software\\SecureLine VPN\\*" OR Image="*:\\Program Files (x86)\\Avast Software\\SecureLine VPN\\*")) OR (Image="*:\\Program Files\\OpenVPN Connect\\drivers\\tap\\*") OR (Image="*:\\Program Files (x86)\\Proton Technologies\\ProtonVPNTap\\installer\\*"))))
    return True

def title(event):
    return "Tap Installer Execution"

