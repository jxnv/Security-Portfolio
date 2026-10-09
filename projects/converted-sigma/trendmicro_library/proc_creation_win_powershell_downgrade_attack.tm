// Title: Potential PowerShell Downgrade Attack
// ID: b3512211-c67e-4707-bedc-66efc7848863
// Status: test
// Level: medium
// Author: Harish Segar (rule)
// Date: 2020-03-20
// Tags: attack.execution, attack.t1059.001
// Description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\powershell.exe" AND (CommandLine: "* -version 2 *" OR CommandLine: "* -versio 2 *" OR CommandLine: "* -versi 2 *" OR CommandLine: "* -vers 2 *" OR CommandLine: "* -ver 2 *" OR CommandLine: "* -ve 2 *" OR CommandLine: "* -v 2 *"))
