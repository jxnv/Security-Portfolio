# Title: Hiding User Account Via SpecialAccounts Registry Key
# ID: f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems), frack113
# Date: 2022-07-12
# Tags: attack.stealth, attack.t1564.002
# Description: Detects modifications to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Hiding User Account Via SpecialAccounts Registry Key
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList*" AND Details="DWORD (0x00000000)")
    return True

def title(event):
    return "Hiding User Account Via SpecialAccounts Registry Key"

