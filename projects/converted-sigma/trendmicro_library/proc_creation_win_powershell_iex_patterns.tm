// Title: Suspicious PowerShell IEX Execution Patterns
// ID: 09576804-7a05-458e-a817-eb718ca91f54
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-03-24
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious ways to run Invoke-Execution using IEX alias
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine: "* | iex;*" OR CommandLine: "* | iex *" OR CommandLine: "* | iex}*" OR CommandLine: "* | IEX ;*" OR CommandLine: "* | IEX -Error*" OR CommandLine: "* | IEX (new*" OR CommandLine: "*);IEX *")) AND ((CommandLine: "*::FromBase64String*" OR CommandLine: "*.GetString([System.Convert]::*"))) OR ((CommandLine: "*)|iex;$*" OR CommandLine: "*);iex($*" OR CommandLine: "*);iex $*" OR CommandLine: "* | IEX | *" OR CommandLine: "* | iex\\\"*")))
