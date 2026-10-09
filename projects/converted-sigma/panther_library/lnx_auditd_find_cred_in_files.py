# Title: Credentials In Files - Linux
# ID: df3fcaea-2715-4214-99c5-0056ea59eb35
# Status: test
# Level: high
# Author: Igor Fits, oscd.community
# Date: 2020-10-15
# Tags: attack.credential-access, attack.t1552.001
# Description: Detecting attempts to extract passwords with grep
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Credentials In Files - Linux
def rule(event):
    # Detection Logic:
    # ((type="EXECVE") AND ((="grep" AND ="password")))
    return True

def title(event):
    return "Credentials In Files - Linux"

