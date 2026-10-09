# Title: Suspicious X509Enrollment - Process Creation
# ID: 114de787-4eb2-48cc-abdb-c0b449f93ea4
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-12-23
# Tags: attack.defense-impairment, attack.t1553.004
# Description: Detect use of X509Enrollment
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious X509Enrollment - Process Creation
def rule(event):
    # Detection Logic:
    # ((CommandLine="*X509Enrollment.CBinaryConverter*" OR CommandLine="*884e2002-217d-11da-b2a4-000e7bbb2b09*"))
    return True

def title(event):
    return "Suspicious X509Enrollment - Process Creation"

