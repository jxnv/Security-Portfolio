# Title: Potential ClickFix Execution Pattern - Registry
# ID: f5fe36cf-f1ec-4c23-903d-09a3110f6bbb
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2025-03-25
# Tags: attack.execution, attack.t1204.001
# Description: Detects potential ClickFix malware execution patterns by monitoring registry modifications in RunMRU keys containing HTTP/HTTPS links.
# ClickFix is known to be distributed through phishing campaigns and uses techniques like clipboard hijacking and fake CAPTCHA pages.
# Through the fakecaptcha pages, the adversary tricks users into opening the Run dialog box and pasting clipboard-hijacked content,
# such as one-liners that execute remotely hosted malicious files or scripts.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential ClickFix Execution Pattern - Registry
def rule(event):
    # Detection Logic:
    # (((Details="*http://*" OR Details="*https://*")) AND (TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") AND (((Details="*account*" OR Details="*anti-bot*" OR Details="*botcheck*" OR Details="*captcha*" OR Details="*challenge*" OR Details="*confirmation*" OR Details="*fraud*" OR Details="*human*" OR Details="*identification*" OR Details="*identificator*" OR Details="*identity*" OR Details="*robot*" OR Details="*validation*" OR Details="*verification*" OR Details="*verify*")) OR ((Details="*%comspec%*" OR Details="*bitsadmin*" OR Details="*certutil*" OR Details="*cmd*" OR Details="*cscript*" OR Details="*curl*" OR Details="*finger*" OR Details="*mshta*" OR Details="*powershell*" OR Details="*pwsh*" OR Details="*regsvr32*" OR Details="*rundll32*" OR Details="*schtasks*" OR Details="*wget*" OR Details="*wscript*"))))
    return True

def title(event):
    return "Potential ClickFix Execution Pattern - Registry"

