// Title: PowerShell SAM Copy
// ID: 1af57a4b-460a-4738-9034-db68b880c665
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-29
// Tags: attack.credential-access, attack.t1003.002
// Description: Detects suspicious PowerShell scripts accessing SAM hives
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*\\HarddiskVolumeShadowCopy*" AND CommandLine: "*System32\\config\\sam*")) AND ((CommandLine: "*Copy-Item*" OR CommandLine: "*cp $_.*" OR CommandLine: "*cpi $_.*" OR CommandLine: "*copy $_.*" OR CommandLine: "*.File]::Copy(*")))
