# Title: Cisco Collect Data
# ID: cd072b25-a418-4f98-8ebc-5093fb38fe1a
# Status: test
# Level: low
# Author: Austin Clark
# Date: 2019-08-11
# Tags: attack.discovery, attack.credential-access, attack.collection, attack.t1087.001, attack.t1552.001, attack.t1005
# Description: Collect pertinent data from the configuration files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cisco Collect Data
def rule(event):
    # Detection Logic:
    # ("show running-config" OR "show startup-config" OR "show archive config" OR "more")
    return True

def title(event):
    return "Cisco Collect Data"

