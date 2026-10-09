# Title: Linux Package Uninstall
# ID: 95d61234-7f56-465c-6f2d-b562c6fedbc4
# Status: test
# Level: low
# Author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-03-09
# Tags: attack.stealth, attack.t1070
# Description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Linux Package Uninstall
def rule(event):
    # Detection Logic:
    # (((Image="*/apt" OR Image="*/apt-get") AND (CommandLine="*remove*" OR CommandLine="*purge*")) OR (Image="*/dpkg" AND (CommandLine="*--remove *" OR CommandLine="* -r *")) OR (Image="*/rpm" AND CommandLine="* -e *") OR (Image="*/yum" AND (CommandLine="*erase*" OR CommandLine="*remove*")))
    return True

def title(event):
    return "Linux Package Uninstall"

