# Title: Data Export From MSSQL Table Via BCP.EXE
# ID: c615d676-f655-46b9-b913-78729021e5d7
# Status: test
# Level: medium
# Author: Omar Khaled (@beacon_exe), MahirAli Khan (in/mahiralikhan), Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-08-20
# Tags: attack.execution, attack.exfiltration, attack.t1048
# Description: Detects the execution of the BCP utility in order to export data from the database.
# Attackers were seen saving their malware to a database column or table and then later extracting it via "bcp.exe" into a file.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Data Export From MSSQL Table Via BCP.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* out *" OR CommandLine="* queryout *")) AND ((Image="*\\bcp.exe") OR (OriginalFileName="BCP.exe")))
    return True

def title(event):
    return "Data Export From MSSQL Table Via BCP.EXE"

