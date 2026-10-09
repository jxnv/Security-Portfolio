# Title: Remote Access Tool - ScreenConnect Command Execution
# ID: 076ebe48-cc05-4d8f-9d41-89245cd93a14
# Status: test
# Level: low
# Author: Ali Alwashali
# Date: 2023-10-10
# Tags: attack.execution, attack.t1059.003
# Description: Detects command execution via ScreenConnect RMM
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote Access Tool - ScreenConnect Command Execution
def rule(event):
    # Detection Logic:
    # (Provider_Name="ScreenConnect" AND EventID="200" AND Data="*Executed command of length*")
    return True

def title(event):
    return "Remote Access Tool - ScreenConnect Command Execution"

