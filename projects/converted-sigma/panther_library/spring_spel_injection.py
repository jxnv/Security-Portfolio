# Title: Potential SpEL Injection In Spring Framework
# ID: e9edd087-89d8-48c9-b0b4-5b9bb10896b8
# Status: test
# Level: high
# Author: Moti Harmats
# Date: 2023-02-11
# Tags: attack.initial-access, attack.t1190
# Description: Detects potential SpEL Injection exploitation, which may lead to RCE.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential SpEL Injection In Spring Framework
def rule(event):
    # Detection Logic:
    # ("org.springframework.expression.ExpressionException")
    return True

def title(event):
    return "Potential SpEL Injection In Spring Framework"

