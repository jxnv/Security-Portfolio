# Title: Chopper Webshell Process Pattern
# ID: fa3c117a-bc0d-416e-a31b-0c0e80653efb
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), MSTI (query)
# Date: 2022-10-01
# Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
# Description: Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Chopper Webshell Process Pattern
def rule(event):
    # Detection Logic:
    # (((CommandLine="*&ipconfig&echo*" OR CommandLine="*&quser&echo*" OR CommandLine="*&whoami&echo*" OR CommandLine="*&c:&echo*" OR CommandLine="*&cd&echo*" OR CommandLine="*&dir&echo*" OR CommandLine="*&echo [E]*" OR CommandLine="*&echo [S]*")) AND ((Image="*\\w3wp.exe") OR (ParentImage="*\\w3wp.exe")))
    return True

def title(event):
    return "Chopper Webshell Process Pattern"

