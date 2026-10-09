# Title: Remove Exported Mailbox from Exchange Webserver
# ID: 09570ae5-889e-43ea-aac0-0e1221fb3d95
# Status: test
# Level: high
# Author: Christian Burkard (Nextron Systems)
# Date: 2021-08-27
# Tags: attack.stealth, attack.t1070
# Description: Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remove Exported Mailbox from Exchange Webserver
def rule(event):
    # Detection Logic:
    # ((="Remove-MailboxExportRequest" AND =" -Identity " AND =" -Confirm \"False\""))
    return True

def title(event):
    return "Remove Exported Mailbox from Exchange Webserver"

