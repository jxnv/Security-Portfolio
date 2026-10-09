// Title: Remote Thread Creation Ttdinject.exe Proxy
// ID: c15e99a3-c474-48ab-b9a7-84549a7a9d16
// Status: test
// Level: high
// Author: frack113
// Date: 2022-05-16
// Tags: attack.execution, attack.stealth, attack.t1127
// Description: Detects a remote thread creation of Ttdinject.exe used as proxy
// Converted by: Sigma Universal SIEM/EDR CLI

(SourceImage="*\\ttdinject.exe")
