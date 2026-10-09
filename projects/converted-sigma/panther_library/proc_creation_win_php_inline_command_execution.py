# Title: Php Inline Command Execution
# ID: d81871ef-5738-47ab-9797-7a9c90cd4bfb
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-01-02
# Tags: attack.execution, attack.t1059
# Description: Detects execution of php using the "-r" flag. This is could be used as a way to launch a reverse shell or execute live php code.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Php Inline Command Execution
def rule(event):
    # Detection Logic:
    # ((CommandLine="* -r*") AND ((Image="*\\php.exe") OR (OriginalFileName="php.exe")))
    return True

def title(event):
    return "Php Inline Command Execution"

