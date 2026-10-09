# Title: DNS Server Discovery Via LDAP Query
# ID: a21bcd7e-38ec-49ad-b69a-9ea17e69509e
# Status: test
# Level: low
# Author: frack113
# Date: 2022-08-20
# Tags: attack.discovery, attack.t1482
# Description: Detects DNS server discovery via LDAP query requests from uncommon applications
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DNS Server Discovery Via LDAP Query
def rule(event):
    # Detection Logic:
    # ((QueryName="_ldap.*") AND NOT (((Image="*:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" AND Image="*\\MsMpEng.exe") OR ((Image="*:\\Program Files\\*" OR Image="*:\\Program Files (x86)\\*" OR Image="*:\\Windows\\*")) OR (NOT Image=*) OR (Image="<unknown process>"))) AND NOT (((Image="C:\\WindowsAzure\\GuestAgent*") OR ((Image="*\\chrome.exe" OR Image="*\\firefox.exe" OR Image="*\\opera.exe")))))
    return True

def title(event):
    return "DNS Server Discovery Via LDAP Query"

