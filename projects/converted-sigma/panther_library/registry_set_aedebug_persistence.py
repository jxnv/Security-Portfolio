# Title: Add Debugger Entry To AeDebug For Persistence
# ID: 092af964-4233-4373-b4ba-d86ea2890288
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-21
# Tags: attack.persistence
# Description: Detects when an attacker adds a new "Debugger" value to the "AeDebug" key in order to achieve persistence which will get invoked when an application crashes
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Add Debugger Entry To AeDebug For Persistence
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger*" AND Details="*.dll") AND NOT ((Details="\"C:\\WINDOWS\\system32\\vsjitdebugger.exe\" -p %ld -e %ld -j 0x%p")))
    return True

def title(event):
    return "Add Debugger Entry To AeDebug For Persistence"

