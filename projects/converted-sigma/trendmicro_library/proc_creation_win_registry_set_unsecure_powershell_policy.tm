// Title: Potential PowerShell Execution Policy Tampering - ProcCreation
// ID: cf2e938e-9a3e-4fe8-a347-411642b28a9f
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.defense-impairment
// Description: Detects changes to the PowerShell execution policy registry key in order to bypass signing requirements for script execution from the CommandLine
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy*" OR CommandLine: "*\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy*")) AND ((CommandLine: "*Bypass*" OR CommandLine: "*RemoteSigned*" OR CommandLine: "*Unrestricted*")))
