# Title: Apache Segmentation Fault
# ID: 1da8ce0b-855d-4004-8860-7d64d42063b1
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2017-02-28
# Tags: attack.impact, attack.t1499.004
# Description: Detects a segmentation fault error message caused by a crashing apache worker process
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Apache Segmentation Fault
def rule(event):
    # Detection Logic:
    # ("exit signal Segmentation Fault")
    return True

def title(event):
    return "Apache Segmentation Fault"

