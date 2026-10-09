# Title: Scheduled Task/Job At
# ID: d2d642d7-b393-43fe-bae4-e81ed5915c4b
# Status: stable
# Level: low
# Author: Ömer Günal, oscd.community
# Date: 2020-10-06
# Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.002
# Description: Detects the use of at/atd which are utilities that are used to schedule tasks.
# They are often abused by adversaries to maintain persistence or to perform task scheduling for initial or recurring execution of malicious code
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Scheduled Task/Job At
def rule(event):
    # Detection Logic:
    # ((Image="*/at" OR Image="*/atd"))
    return True

def title(event):
    return "Scheduled Task/Job At"

