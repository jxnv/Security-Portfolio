// Title: Potential Privilege Escalation To LOCAL SYSTEM
// ID: 207b0396-3689-42d9-8399-4222658efc99
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-05-22
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects unknown program using commandline flags usually used by tools such as PsExec and PAExec to start programs with SYSTEM Privileges
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "* -s cmd*" OR CommandLine: "* -s -i cmd*" OR CommandLine: "* -i -s cmd*" OR CommandLine: "* -s pwsh*" OR CommandLine: "* -s -i pwsh*" OR CommandLine: "* -i -s pwsh*" OR CommandLine: "* -s powershell*" OR CommandLine: "* -s -i powershell*" OR CommandLine: "* -i -s powershell*")) AND NOT (((CommandLine: "*paexec*" OR CommandLine: "*PsExec*" OR CommandLine: "*accepteula*"))))
