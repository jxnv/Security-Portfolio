# Title: Suspicious PowerShell Mailbox Export to Share
# ID: 889719ef-dd62-43df-86c3-768fb08dc7c0
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2021-08-07
# Tags: attack.exfiltration
# Description: Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Mailbox Export to Share
def rule(event):
    # Detection Logic:
    # ((CommandLine="*New-MailboxExportRequest*" AND CommandLine="* -Mailbox *" AND CommandLine="* -FilePath \\\\\\\\*"))
    return True

def title(event):
    return "Suspicious PowerShell Mailbox Export to Share"

