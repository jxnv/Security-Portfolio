# Title: Potential AMSI Bypass Via .NET Reflection
# ID: 30edb182-aa75-42c0-b0a9-e998bb29067c
# Status: test
# Level: high
# Author: Markus Neis, @Kostastsale
# Date: 2018-08-17
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential AMSI Bypass Via .NET Reflection
def rule(event):
    # Detection Logic:
    # (((CommandLine="*System.Management.Automation.AmsiUtils*" AND CommandLine="*amsiInitFailed*")) OR ((CommandLine="*[Ref].Assembly.GetType*" AND CommandLine="*SetValue($null,$true)*" AND CommandLine="*NonPublic,Static*")))
    return True

def title(event):
    return "Potential AMSI Bypass Via .NET Reflection"

