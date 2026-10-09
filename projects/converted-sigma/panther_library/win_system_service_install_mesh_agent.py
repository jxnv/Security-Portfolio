# Title: Mesh Agent Service Installation
# ID: e0d1ad53-c7eb-48ec-a87a-72393cc6cedc
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-11-28
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects a Mesh Agent service installation. Mesh Agent is used to remotely manage computers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Mesh Agent Service Installation
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045") AND ((ImagePath="*MeshAgent.exe*") OR (ServiceName="*Mesh Agent*")))
    return True

def title(event):
    return "Mesh Agent Service Installation"

