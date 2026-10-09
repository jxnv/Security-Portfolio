# Title: Suspicious X509Enrollment - Ps Script
# ID: 504d63cb-0dba-4d02-8531-e72981aace2c
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-12-23
# Tags: attack.defense-impairment, attack.t1553.004
# Description: Detect use of X509Enrollment
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious X509Enrollment - Ps Script
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*X509Enrollment.CBinaryConverter*" OR ScriptBlockText="*884e2002-217d-11da-b2a4-000e7bbb2b09*"))
    return True

def title(event):
    return "Suspicious X509Enrollment - Ps Script"

