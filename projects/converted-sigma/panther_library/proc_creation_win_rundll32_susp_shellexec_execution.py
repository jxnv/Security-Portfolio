# Title: Suspicious Usage Of ShellExec_RunDLL
# ID: d87bd452-6da1-456e-8155-7dc988157b7d
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-01
# Tags: attack.stealth
# Description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Usage Of ShellExec_RunDLL
def rule(event):
    # Detection Logic:
    # ((CommandLine="*ShellExec_RunDLL*") AND ((CommandLine="*\\Desktop\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\Users\\Public\\*" OR CommandLine="*comspec*" OR CommandLine="*iex*" OR CommandLine="*Invoke-*" OR CommandLine="*msiexec*" OR CommandLine="*odbcconf*" OR CommandLine="*regsvr32*")))
    return True

def title(event):
    return "Suspicious Usage Of ShellExec_RunDLL"

