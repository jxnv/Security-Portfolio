# Title: Suspicious High IntegrityLevel Conhost Legacy Option
# ID: 3037d961-21e9-4732-b27a-637bcc7bf539
# Status: test
# Level: informational
# Author: frack113
# Date: 2022-12-09
# Tags: attack.stealth, attack.t1202
# Description: ForceV1 asks for information directly from the kernel space. Conhost connects to the console application. High IntegrityLevel means the process is running with elevated privileges, such as an Administrator context.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious High IntegrityLevel Conhost Legacy Option
def rule(event):
    # Detection Logic:
    # ((IntegrityLevel="High" OR IntegrityLevel="S-1-16-12288") AND (CommandLine="*conhost.exe*" AND CommandLine="*0xffffffff*" AND CommandLine="*-ForceV1*"))
    return True

def title(event):
    return "Suspicious High IntegrityLevel Conhost Legacy Option"

