# Title: Powershell Token Obfuscation - Process Creation
# ID: deb9b646-a508-44ee-b7c9-d8965921c6b6
# Status: test
# Level: high
# Author: frack113
# Date: 2022-12-27
# Tags: attack.stealth, attack.t1027.009
# Description: Detects TOKEN OBFUSCATION technique from Invoke-Obfuscation
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Token Obfuscation - Process Creation
def rule(event):
    # Detection Logic:
    # (((CommandLine=regex("\\w+`(?:\\w+|-|.)`[\\w+|\\s]")) OR (CommandLine=regex("\"(?:\\{\\d\\})+\"\\s*-f")) OR (CommandLine=regex("(?i)\\$\\{`?e`?n`?v`?:`?p`?a`?t`?h`?\\}"))) AND NOT ((CommandLine="*${env:path}*")))
    return True

def title(event):
    return "Powershell Token Obfuscation - Process Creation"

