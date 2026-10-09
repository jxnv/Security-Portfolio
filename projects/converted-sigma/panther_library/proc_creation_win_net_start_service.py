# Title: Start Windows Service Via Net.EXE
# ID: 2a072a96-a086-49fa-bcb5-15cc5a619093
# Status: test
# Level: low
# Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
# Date: 2019-10-21
# Tags: attack.execution, attack.t1569.002
# Description: Detects the usage of the "net.exe" command to start a service using the "start" flag
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Start Windows Service Via Net.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="* start *") AND (((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName="net.exe" OR OriginalFileName="net1.exe"))))
    return True

def title(event):
    return "Start Windows Service Via Net.EXE"

