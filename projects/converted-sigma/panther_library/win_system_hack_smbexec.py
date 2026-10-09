# Title: smbexec.py Service Installation
# ID: 52a85084-6989-40c3-8f32-091e12e13f09
# Status: test
# Level: high
# Author: Omer Faruk Celik
# Date: 2018-03-20
# Tags: attack.lateral-movement, attack.execution, attack.t1021.002, attack.t1569.002
# Description: Detects the use of smbexec.py tool by detecting a specific service installation
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: smbexec.py Service Installation
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045") AND (((ImagePath="*.bat & del *" OR ImagePath="*__output 2^>^&1 >*")) OR (ServiceName="BTOBTO")))
    return True

def title(event):
    return "smbexec.py Service Installation"

