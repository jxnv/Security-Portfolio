# Title: Potential Persistence Via Outlook Home Page
# ID: ddd171b5-2cc6-4975-9e78-f0eccd08cc76
# Status: test
# Level: high
# Author: Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand
# Date: 2021-06-09
# Tags: attack.persistence, attack.defense-impairment, attack.t1112
# Description: Detects potential persistence activity via outlook home page.
# An attacker can set a home page to achieve code execution and persistence by editing the WebView registry keys.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via Outlook Home Page
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\Software\\Microsoft\\Office\\*" AND TargetObject="*\\Outlook\\WebView\\*") AND TargetObject="*\\URL")
    return True

def title(event):
    return "Potential Persistence Via Outlook Home Page"

