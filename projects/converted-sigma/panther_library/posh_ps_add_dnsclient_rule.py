# Title: Powershell Add Name Resolution Policy Table Rule
# ID: 4368354e-1797-463c-bc39-a309effbe8d7
# Status: test
# Level: high
# Author: Borna Talebi
# Date: 2021-09-14
# Tags: attack.impact, attack.t1565
# Description: Detects powershell scripts that adds a Name Resolution Policy Table (NRPT) rule for the specified namespace.
# This will bypass the default DNS server and uses a specified server for answering the query.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Add Name Resolution Policy Table Rule
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Add-DnsClientNrptRule*" AND ScriptBlockText="*-Namesp*" AND ScriptBlockText="*-NameSe*"))
    return True

def title(event):
    return "Powershell Add Name Resolution Policy Table Rule"

