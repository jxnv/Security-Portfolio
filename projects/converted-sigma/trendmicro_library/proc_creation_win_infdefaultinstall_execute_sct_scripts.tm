// Title: InfDefaultInstall.exe .inf Execution
// ID: ce7cf472-6fcc-490a-9481-3786840b5d9b
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-13
// Tags: attack.stealth, attack.t1218
// Description: Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*InfDefaultInstall.exe *" AND CommandLine: "*.inf*"))
