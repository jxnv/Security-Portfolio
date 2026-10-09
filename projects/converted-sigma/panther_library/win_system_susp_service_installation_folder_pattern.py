# Title: Service Installation with Suspicious Folder Pattern
# ID: 1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2
# Status: test
# Level: high
# Author: pH-T (Nextron Systems)
# Date: 2022-03-18
# Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
# Description: Detects service installation with suspicious folder patterns
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service Installation with Suspicious Folder Pattern
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045") AND ((ImagePath=regex("^[Cc]:\\\\[Pp]rogram[Dd]ata\\\\.{1,9}\\.exe")) OR (ImagePath=regex("^[Cc]:\\\\.{1,9}\\.exe"))))
    return True

def title(event):
    return "Service Installation with Suspicious Folder Pattern"

