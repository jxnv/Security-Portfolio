# Title: Suspicious History File Operations
# ID: 508a9374-ad52-4789-b568-fc358def2c65
# Status: test
# Level: medium
# Author: Mikhail Larin, oscd.community
# Date: 2020-10-17
# Tags: attack.credential-access, attack.t1552.003
# Description: Detects commandline operations on shell history files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious History File Operations
def rule(event):
    # Detection Logic:
    # ((CommandLine="*.bash_history*" OR CommandLine="*.zsh_history*" OR CommandLine="*.zhistory*" OR CommandLine="*.history*" OR CommandLine="*.sh_history*" OR CommandLine="*fish_history*"))
    return True

def title(event):
    return "Suspicious History File Operations"

