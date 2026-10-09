// Title: Indirect Command Execution From Script File Via Bash.EXE
// ID: 2d22a514-e024-4428-9dba-41505bd63a5b
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-15
// Tags: attack.stealth, attack.t1202
// Description: Detects execution of Microsoft bash launcher without any flags to execute the content of a bash script directly.
// This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*:\\Windows\\System32\\bash.exe" OR Image="*:\\Windows\\SysWOW64\\bash.exe")) OR (OriginalFileName: "Bash.exe")) AND NOT ((((CommandLine: "*bash.exe -*" OR CommandLine: "*bash -*")) OR (CommandLine: "") OR (NOT CommandLine=*) OR ((CommandLine: "bash.exe" OR CommandLine: "bash")))))
