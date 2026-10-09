# Title: Potential Renamed Rundll32 Execution
# ID: 2569ed8c-1147-498a-9b8c-2ad3656b10ed
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-22
# Tags: attack.execution
# Description: Detects when 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Renamed Rundll32 Execution
def rule(event):
    # Detection Logic:
    # ((CommandLine="*DllRegisterServer*") AND NOT ((Image="*\\rundll32.exe")))
    return True

def title(event):
    return "Potential Renamed Rundll32 Execution"

