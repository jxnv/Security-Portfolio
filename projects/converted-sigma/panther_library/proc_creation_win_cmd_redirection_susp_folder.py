# Title: Potentially Suspicious CMD Shell Output Redirect
# ID: 8e0bb260-d4b2-4fff-bb8d-3f82118e6892
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-12
# Tags: attack.stealth, attack.t1218
# Description: Detects inline Windows shell commands redirecting output via the ">" symbol to a suspicious location.
# This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as "hostname" and "dir" to files for future exfiltration.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious CMD Shell Output Redirect
def rule(event):
    # Detection Logic:
    # (((Image="*\\cmd.exe") OR (OriginalFileName="Cmd.Exe")) AND (((CommandLine="*>?%APPDATA%\\*" OR CommandLine="*>?%TEMP%\\*" OR CommandLine="*>?%TMP%\\*" OR CommandLine="*>?%USERPROFILE%\\*" OR CommandLine="*>?C:\\ProgramData\\*" OR CommandLine="*>?C:\\Temp\\*" OR CommandLine="*>?C:\\Users\\Public\\*" OR CommandLine="*>?C:\\Windows\\Temp\\*")) OR ((CommandLine="* >*" OR CommandLine="*\">*" OR CommandLine="*'>*") AND (CommandLine="*C:\\Users\\*" AND CommandLine="*\\AppData\\Local\\*"))))
    return True

def title(event):
    return "Potentially Suspicious CMD Shell Output Redirect"

