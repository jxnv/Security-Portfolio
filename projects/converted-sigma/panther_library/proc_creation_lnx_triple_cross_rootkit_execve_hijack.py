# Title: Triple Cross eBPF Rootkit Execve Hijack
# ID: 0326c3c8-7803-4a0f-8c5c-368f747f7c3e
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-05
# Tags: attack.privilege-escalation, attack.stealth
# Description: Detects execution of a the file "execve_hijack" which is used by the Triple Cross rootkit as a way to elevate privileges
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Triple Cross eBPF Rootkit Execve Hijack
def rule(event):
    # Detection Logic:
    # (Image="*/sudo" AND CommandLine="*execve_hijack*")
    return True

def title(event):
    return "Triple Cross eBPF Rootkit Execve Hijack"

