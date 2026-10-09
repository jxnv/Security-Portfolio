# Title: Potentially Suspicious Usage Of Qemu
# ID: 5fc297ae-25b6-488a-8f25-cc12ac29b744
# Status: test
# Level: medium
# Author: Muhammad Faisal (@faisalusuf), Hunter Juhan (@threatHNTR)
# Date: 2024-06-03
# Tags: attack.command-and-control, attack.t1090, attack.t1572
# Description: Detects potentially suspicious execution of the Qemu utility in a Windows environment.
# Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious Usage Of Qemu
def rule(event):
    # Detection Logic:
    # (((CommandLine="*-m 1M*" OR CommandLine="*-m 2M*" OR CommandLine="*-m 3M*") AND (CommandLine="*restrict=off*" AND CommandLine="*-netdev *" AND CommandLine="*connect=*" AND CommandLine="*-nographic*")) AND NOT (((CommandLine="* -cdrom *" OR CommandLine="* type=virt *" OR CommandLine="* -blockdev *"))))
    return True

def title(event):
    return "Potentially Suspicious Usage Of Qemu"

