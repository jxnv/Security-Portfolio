// Title: Suspicious DLL Loaded via CertOC.EXE
// ID: 84232095-ecca-4015-b0d7-7726507ee793
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-15
// Tags: attack.stealth, attack.t1218
// Description: Detects when a user installs certificates by using CertOC.exe to load the target DLL file.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "* -LoadDLL *") AND ((Image="*\\certoc.exe") OR (OriginalFileName: "CertOC.exe")) AND ((CommandLine: "*\\Appdata\\Local\\Temp\\*" OR CommandLine: "*\\Desktop\\*" OR CommandLine: "*\\Downloads\\*" OR CommandLine: "*\\Users\\Public\\*" OR CommandLine: "*C:\\Windows\\Tasks\\*" OR CommandLine: "*C:\\Windows\\Temp\\*")))
