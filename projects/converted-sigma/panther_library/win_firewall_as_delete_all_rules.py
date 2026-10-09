# Title: All Rules Have Been Deleted From The Windows Firewall Configuration
# ID: 79609c82-a488-426e-abcf-9f341a39365d
# Status: test
# Level: high
# Author: frack113, Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-17
# Tags: attack.defense-impairment, attack.t1686.003
# Description: Detects when a all the rules have been deleted from the Windows Defender Firewall configuration
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: All Rules Have Been Deleted From The Windows Firewall Configuration
def rule(event):
    # Detection Logic:
    # (((EventID="2033" OR EventID="2059")) AND NOT ((ModifyingApplication="*:\\Windows\\System32\\svchost.exe")) AND NOT (((ModifyingApplication="*:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" AND ModifyingApplication="*\\MsMpEng.exe*"))))
    return True

def title(event):
    return "All Rules Have Been Deleted From The Windows Firewall Configuration"

