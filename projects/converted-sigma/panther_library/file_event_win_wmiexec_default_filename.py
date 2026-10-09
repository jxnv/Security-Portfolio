# Title: Wmiexec Default Output File
# ID: 8d5aca11-22b3-4f22-b7ba-90e60533e1fb
# Status: test
# Level: critical
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-02
# Tags: attack.lateral-movement, attack.execution, attack.t1047
# Description: Detects the creation of the default output filename used by the wmiexec tool
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Wmiexec Default Output File
def rule(event):
    # Detection Logic:
    # ((TargetFilename=regex("\\\\Windows\\\\__1\\d{9}\\.\\d{1,7}$")) OR (TargetFilename=regex("C:\\\\__1\\d{9}\\.\\d{1,7}$")) OR (TargetFilename=regex("D:\\\\__1\\d{9}\\.\\d{1,7}$")))
    return True

def title(event):
    return "Wmiexec Default Output File"

