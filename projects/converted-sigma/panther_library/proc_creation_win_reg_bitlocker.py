# Title: Suspicious Reg Add BitLocker
# ID: 0e0255bf-2548-47b8-9582-c0955c9283f5
# Status: test
# Level: high
# Author: frack113
# Date: 2021-11-15
# Tags: attack.impact, attack.t1486
# Description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Reg Add BitLocker
def rule(event):
    # Detection Logic:
    # ((CommandLine="*REG*" AND CommandLine="*ADD*" AND CommandLine="*\\SOFTWARE\\Policies\\Microsoft\\FVE*" AND CommandLine="*/v*" AND CommandLine="*/f*") AND (CommandLine="*EnableBDEWithNoTPM*" OR CommandLine="*UseAdvancedStartup*" OR CommandLine="*UseTPM*" OR CommandLine="*UseTPMKey*" OR CommandLine="*UseTPMKeyPIN*" OR CommandLine="*RecoveryKeyMessageSource*" OR CommandLine="*UseTPMPIN*" OR CommandLine="*RecoveryKeyMessage*"))
    return True

def title(event):
    return "Suspicious Reg Add BitLocker"

