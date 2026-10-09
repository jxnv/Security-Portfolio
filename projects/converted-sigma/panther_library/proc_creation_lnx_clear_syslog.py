# Title: Syslog Clearing or Removal Via System Utilities
# ID: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
# Status: test
# Level: high
# Author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
# Date: 2021-10-15
# Tags: attack.defense-impairment, attack.t1685.006
# Description: Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Syslog Clearing or Removal Via System Utilities
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/var/log/syslog*") AND ((Image="*/cp" AND CommandLine="*/dev/null*") OR (Image="*/ln" AND (CommandLine="*/dev/null *" AND CommandLine="*/var/log/syslog*") AND (CommandLine="*-sf *" OR CommandLine="*-sfn *" OR CommandLine="*-sfT *")) OR (Image="*/mv") OR (Image="*/rm" AND (CommandLine="* -r *" OR CommandLine="* -f *" OR CommandLine="* -rf *" OR CommandLine="*/var/log/syslog*")) OR (Image="*/shred" AND CommandLine="*-u *") OR (Image="*/truncate" AND (CommandLine="*0 *" AND CommandLine="*/var/log/syslog*") AND (CommandLine="*-s *" OR CommandLine="*-c *" OR CommandLine="*--size*")) OR (Image="*/unlink"))) OR (((CommandLine="*journalctl --vacuum*" OR CommandLine="*journalctl --rotate*")) OR ((CommandLine="* > /var/log/syslog*" OR CommandLine="* >/var/log/syslog*" OR CommandLine="* >| /var/log/syslog*" OR CommandLine="*: > /var/log/syslog*" OR CommandLine="*:> /var/log/syslog*" OR CommandLine="*:>/var/log/syslog*" OR CommandLine="*>|/var/log/syslog*"))))
    return True

def title(event):
    return "Syslog Clearing or Removal Via System Utilities"

