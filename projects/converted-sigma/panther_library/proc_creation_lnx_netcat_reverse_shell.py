# Title: Potential Netcat Reverse Shell Execution
# ID: 7f734ed0-4f47-46c0-837f-6ee62505abd9
# Status: test
# Level: high
# Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-04-07
# Tags: attack.execution, attack.t1059
# Description: Detects execution of netcat with the "-e" or "-c" flags followed by common shells, which are commonly used to spawn reverse shells.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Netcat Reverse Shell Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -c *" OR CommandLine="* -e *")) AND ((Image="*/nc.openbsd" OR Image="*/nc.traditional" OR Image="*/nc" OR Image="*/ncat" OR Image="*/netcat.openbsd" OR Image="*/netcat.traditional" OR Image="*/netcat")) AND ((CommandLine="* ash*" OR CommandLine="* bash*" OR CommandLine="* bsh*" OR CommandLine="* csh*" OR CommandLine="* ksh*" OR CommandLine="* pdksh*" OR CommandLine="* sh*" OR CommandLine="* tcsh*" OR CommandLine="*/bin/ash*" OR CommandLine="*/bin/bash*" OR CommandLine="*/bin/bsh*" OR CommandLine="*/bin/csh*" OR CommandLine="*/bin/ksh*" OR CommandLine="*/bin/pdksh*" OR CommandLine="*/bin/sh*" OR CommandLine="*/bin/tcsh*" OR CommandLine="*/bin/zsh*" OR CommandLine="*$IFSash*" OR CommandLine="*$IFSbash*" OR CommandLine="*$IFSbsh*" OR CommandLine="*$IFScsh*" OR CommandLine="*$IFSksh*" OR CommandLine="*$IFSpdksh*" OR CommandLine="*$IFSsh*" OR CommandLine="*$IFStcsh*" OR CommandLine="*$IFSzsh*")))
    return True

def title(event):
    return "Potential Netcat Reverse Shell Execution"

