# Title: Suspicious FileFix Execution Pattern
# ID: b5b29e4e-31fa-4fdf-b058-296e7a1aa0c2
# Status: experimental
# Level: high
# Author: 0xFustang, Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-11-24
# Tags: attack.execution, attack.t1204.004
# Description: Detects suspicious FileFix execution patterns where users are tricked into running malicious commands through browser file upload dialog manipulation.
# This attack typically begins when users visit malicious websites impersonating legitimate services or news platforms,
# which may display fake CAPTCHA challenges or direct instructions to open file explorer and paste clipboard content.
# The clipboard content usually contains commands that download and execute malware, such as information stealing tools.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious FileFix Execution Pattern
def rule(event):
    # Detection Logic:
    # (((ParentImage="*\\brave.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe" OR ParentImage="*\\msedge.exe") AND CommandLine="*#*") AND (((CommandLine="*account*" OR CommandLine="*anti-bot*" OR CommandLine="*botcheck*" OR CommandLine="*captcha*" OR CommandLine="*challenge*" OR CommandLine="*confirmation*" OR CommandLine="*fraud*" OR CommandLine="*human*" OR CommandLine="*identification*" OR CommandLine="*identificator*" OR CommandLine="*identity*" OR CommandLine="*robot*" OR CommandLine="*validation*" OR CommandLine="*verification*" OR CommandLine="*verify*")) OR ((CommandLine="*%comspec%*" OR CommandLine="*bitsadmin*" OR CommandLine="*certutil*" OR CommandLine="*cmd*" OR CommandLine="*cscript*" OR CommandLine="*curl*" OR CommandLine="*finger*" OR CommandLine="*mshta*" OR CommandLine="*powershell*" OR CommandLine="*pwsh*" OR CommandLine="*regsvr32*" OR CommandLine="*rundll32*" OR CommandLine="*schtasks*" OR CommandLine="*wget*" OR CommandLine="*wscript*"))))
    return True

def title(event):
    return "Suspicious FileFix Execution Pattern"

