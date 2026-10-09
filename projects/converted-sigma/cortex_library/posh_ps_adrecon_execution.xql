// Title: PowerShell ADRecon Execution
// ID: bf72941a-cba0-41ea-b18c-9aca3925690d
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2021-07-16
// Tags: attack.discovery, attack.execution, attack.t1059.001
// Description: Detects execution of ADRecon.ps1 for AD reconnaissance which has been reported to be actively used by FIN7
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Function Get-ADRExcelComOb" or ScriptBlockText contains "Get-ADRGPO" or ScriptBlockText contains "Get-ADRDomainController" or ScriptBlockText contains "ADRecon-Report.xlsx"))
