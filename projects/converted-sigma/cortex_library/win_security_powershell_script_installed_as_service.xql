// Title: PowerShell Scripts Installed as Services - Security
// ID: 2a926e6a-4b81-4011-8a96-e36cc8c04302
// Status: test
// Level: high
// Author: oscd.community, Natalia Shornikova
// Date: 2020-10-06
// Tags: attack.execution, attack.t1569.002
// Description: Detects powershell script installed as a Service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4697 and (ServiceFileName contains "powershell" or ServiceFileName contains "pwsh"))
