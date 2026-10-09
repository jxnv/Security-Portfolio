# Title: Potential Persistence Via CHM Helper DLL
# ID: 976dd1f2-a484-45ec-aa1d-0e87e882262b
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-21
# Tags: attack.persistence
# Description: Detects when an attacker modifies the registry key "HtmlHelp Author" to achieve persistence
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via CHM Helper DLL
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\Software\\Microsoft\\HtmlHelp Author\\Location*" OR TargetObject="*\\Software\\WOW6432Node\\Microsoft\\HtmlHelp Author\\Location*"))
    return True

def title(event):
    return "Potential Persistence Via CHM Helper DLL"

