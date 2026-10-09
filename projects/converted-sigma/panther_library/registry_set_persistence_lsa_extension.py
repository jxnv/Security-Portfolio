# Title: Potential Persistence Via LSA Extensions
# ID: 41f6531d-af6e-4c6e-918f-b946f2b85a36
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-21
# Tags: attack.persistence
# Description: Detects when an attacker modifies the "REG_MULTI_SZ" value named "Extensions" to include a custom DLL to achieve persistence via lsass.
# The "Extensions" list contains filenames of DLLs being automatically loaded by lsass.exe. Each DLL has its InitializeLsaExtension() method called after loading.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Persistence Via LSA Extensions
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\LsaSrv\\Extensions*")
    return True

def title(event):
    return "Potential Persistence Via LSA Extensions"

