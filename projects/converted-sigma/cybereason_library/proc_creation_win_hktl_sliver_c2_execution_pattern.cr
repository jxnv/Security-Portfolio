// Title: HackTool - Sliver C2 Implant Activity Pattern
// ID: 42333b2c-b425-441c-b70e-99404a17170f
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2022-08-25
// Tags: attack.execution, attack.t1059
// Description: Detects process activity patterns as seen being used by Sliver C2 framework implants
// Converted by: Sigma Universal SIEM/EDR CLI

(CommandLine contains "-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8")
