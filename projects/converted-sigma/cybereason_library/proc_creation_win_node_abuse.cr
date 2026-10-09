// Title: Potential Arbitrary Code Execution Via Node.EXE
// ID: 6640f31c-01ad-49b5-beb5-83498a5cd8bd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects the execution node.exe which is shipped with multiple software such as VMware, Adobe...etc. In order to execute arbitrary code. For example to establish reverse shell as seen in Log4j attacks...etc
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\node.exe" AND (CommandLine contains " -e " OR CommandLine contains " --eval ")) AND ((CommandLine contains ".exec(" AND CommandLine contains "net.socket" AND CommandLine contains ".connect" AND CommandLine contains "child_process")))
