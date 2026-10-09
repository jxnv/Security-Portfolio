# Title: Potential NTLM Coercion Via Certutil.EXE
# ID: 6c6d9280-e6d0-4b9d-80ac-254701b64916
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-01
# Tags: attack.stealth, attack.t1218
# Description: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential NTLM Coercion Via Certutil.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -syncwithWU *" AND CommandLine="* \\\\\\\\*")) AND ((Image="*\\certutil.exe") OR (OriginalFileName="CertUtil.exe")))
    return True

def title(event):
    return "Potential NTLM Coercion Via Certutil.EXE"

