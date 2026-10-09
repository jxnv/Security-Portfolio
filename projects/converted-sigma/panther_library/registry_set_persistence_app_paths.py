# Title: Potential Persistence Via App Paths Default Property
# ID: 707e097c-e20f-4f67-8807-1f72ff4500d6
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-10
# Tags: attack.privilege-escalation, attack.persistence, attack.t1546.012
# Description: Detects changes to the "Default" property for keys located in the \Software\Microsoft\Windows\CurrentVersion\App Paths\ registry. Which might be used as a method of persistence
# The entries found under App Paths are used primarily for the following purposes.
# First, to map an application's executable file name to that file's fully qualified path.
# Second, to prepend information to the PATH environment variable on a per-application, per-process basis.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via App Paths Default Property
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths*" AND (TargetObject="*(Default)" OR TargetObject="*Path") AND (Details="*\\Users\\Public*" OR Details="*\\AppData\\Local\\Temp\\*" OR Details="*\\Windows\\Temp\\*" OR Details="*\\Desktop\\*" OR Details="*\\Downloads\\*" OR Details="*%temp%*" OR Details="*%tmp%*" OR Details="*iex*" OR Details="*Invoke-*" OR Details="*rundll32*" OR Details="*regsvr32*" OR Details="*mshta*" OR Details="*cscript*" OR Details="*wscript*" OR Details="*.bat*" OR Details="*.hta*" OR Details="*.dll*" OR Details="*.ps1*"))
    return True

def title(event):
    return "Potential Persistence Via App Paths Default Property"

