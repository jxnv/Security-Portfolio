# Title: Suspicious TCP Tunnel Via PowerShell Script
# ID: bd33d2aa-497e-4651-9893-5c5364646595
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-08
# Tags: attack.command-and-control, attack.t1090
# Description: Detects powershell scripts that creates sockets/listeners which could be indicative of tunneling activity
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious TCP Tunnel Via PowerShell Script
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*[System.Net.HttpWebRequest]*" AND ScriptBlockText="*System.Net.Sockets.TcpListener*" AND ScriptBlockText="*AcceptTcpClient*"))
    return True

def title(event):
    return "Suspicious TCP Tunnel Via PowerShell Script"

