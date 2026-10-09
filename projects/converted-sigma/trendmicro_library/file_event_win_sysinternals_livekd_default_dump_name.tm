// Title: LiveKD Kernel Memory Dump File Created
// ID: 814ddeca-3d31-4265-8e07-8cc54fb44903
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-16
// Tags: attack.privilege-escalation, attack.stealth
// Description: Detects the creation of a file that has the same name as the default LiveKD kernel memory dump.
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetFilename: "C:\\Windows\\livekd.dmp")
