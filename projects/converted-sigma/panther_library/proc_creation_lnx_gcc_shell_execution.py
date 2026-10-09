# Title: Shell Execution GCC  - Linux
# ID: 9b5de532-a757-4d70-946c-1f3e44f48b4d
# Status: test
# Level: high
# Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
# Date: 2024-09-02
# Tags: attack.discovery, attack.t1083
# Description: Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Shell Execution GCC  - Linux
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/bin/bash,-s*" OR CommandLine="*/bin/dash,-s*" OR CommandLine="*/bin/fish,-s*" OR CommandLine="*/bin/sh,-s*" OR CommandLine="*/bin/zsh,-s*")) AND ((Image="*/c89" OR Image="*/c99" OR Image="*/gcc") AND CommandLine="*-wrapper*"))
    return True

def title(event):
    return "Shell Execution GCC  - Linux"

