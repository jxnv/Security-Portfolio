// Title: PowerShell as a Service in Registry
// ID: 4a5f5a5e-ac01-474b-9b4e-d61298c9df1d
// Status: test
// Level: high
// Author: oscd.community, Natalia Shornikova
// Date: 2020-10-06
// Tags: attack.execution, attack.t1569.002
// Description: Detects that a powershell code is written to the registry as a service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\Services\\" and TargetObject endswith "\\ImagePath" and (Details contains "powershell" or Details contains "pwsh"))
