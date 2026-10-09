// Title: Sysinternals PsSuspend Suspicious Execution
// ID: 4beb6ae0-f85b-41e2-8f18-8668abc8af78
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-23
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects suspicious execution of Sysinternals PsSuspend, where the utility is used to suspend critical processes such as AV or EDR to bypass defenses
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*msmpeng.exe*") AND ((OriginalFileName: "pssuspend.exe") OR ((Image="*\\pssuspend.exe" OR Image="*\\pssuspend64.exe" OR Image="*\\pssuspend64a.exe"))))
