# Title: Microsoft Teams Sensitive File Access By Uncommon Applications
# ID: 65744385-8541-44a6-8630-ffc824d7d4cc
# Status: test
# Level: medium
# Author: @SerkinValery
# Date: 2024-07-22
# Tags: attack.credential-access, attack.t1528
# Description: Detects file access attempts to sensitive Microsoft teams files (leveldb, cookies) by an uncommon process.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Microsoft Teams Sensitive File Access By Uncommon Applications
def rule(event):
    # Detection Logic:
    # (((FileName="*\\Microsoft\\Teams\\Cookies*" OR FileName="*\\Microsoft\\Teams\\Local Storage\\leveldb*")) AND NOT ((Image="*\\Microsoft\\Teams\\current\\Teams.exe")))
    return True

def title(event):
    return "Microsoft Teams Sensitive File Access By Uncommon Applications"

