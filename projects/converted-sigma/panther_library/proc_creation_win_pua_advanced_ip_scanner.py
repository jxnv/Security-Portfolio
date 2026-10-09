# Title: PUA - Advanced IP Scanner Execution
# ID: bef37fa2-f205-4a7b-b484-0759bfd5f86f
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), @ROxPinTeddy
# Date: 2020-05-12
# Tags: attack.discovery, attack.t1046, attack.t1135
# Description: Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PUA - Advanced IP Scanner Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/portable*" AND CommandLine="*/lng*")) OR ((Image="*\\advanced_ip_scanner*") OR (OriginalFileName="*advanced_ip_scanner*") OR (Description="*Advanced IP Scanner*")))
    return True

def title(event):
    return "PUA - Advanced IP Scanner Execution"

