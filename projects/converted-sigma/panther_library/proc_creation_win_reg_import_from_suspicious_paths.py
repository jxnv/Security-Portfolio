# Title: Potential Suspicious Registry File Imported Via Reg.EXE
# ID: 62e0298b-e994-4189-bc87-bc699aa62d97
# Status: test
# Level: medium
# Author: frack113, Nasreddine Bencherchali
# Date: 2022-08-01
# Tags: attack.persistence, attack.defense-impairment, attack.t1112
# Description: Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Suspicious Registry File Imported Via Reg.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="* import *") AND ((Image="*\\reg.exe") OR (OriginalFileName="reg.exe")) AND ((CommandLine="*C:\\Users\\*" OR CommandLine="*%temp%*" OR CommandLine="*%tmp%*" OR CommandLine="*%appdata%*" OR CommandLine="*\\AppData\\Local\\Temp\\*" OR CommandLine="*C:\\Windows\\Temp\\*" OR CommandLine="*C:\\ProgramData\\*")))
    return True

def title(event):
    return "Potential Suspicious Registry File Imported Via Reg.EXE"

