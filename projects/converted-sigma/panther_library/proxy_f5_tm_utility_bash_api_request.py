# Title: F5 BIG-IP iControl Rest API Command Execution - Proxy
# ID: b59c98c6-95e8-4d65-93ee-f594dfb96b17
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Thurein Oo
# Date: 2023-11-08
# Tags: attack.initial-access, attack.t1190
# Description: Detects POST requests to the F5 BIG-IP iControl Rest API "bash" endpoint, which allows the execution of commands on the BIG-IP
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: F5 BIG-IP iControl Rest API Command Execution - Proxy
def rule(event):
    # Detection Logic:
    # (cs-method="POST" AND c-uri="*/mgmt/tm/util/bash")
    return True

def title(event):
    return "F5 BIG-IP iControl Rest API Command Execution - Proxy"

