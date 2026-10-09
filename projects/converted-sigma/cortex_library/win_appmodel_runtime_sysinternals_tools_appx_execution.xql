// Title: Sysinternals Tools AppX Versions Execution
// ID: d29a20b2-be4b-4827-81f2-3d8a59eab5fc
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-16
// Tags: attack.execution, attack.stealth
// Description: Detects execution of Sysinternals tools via an AppX package.
// Attackers could install the Sysinternals Suite to get access to tools such as psexec and procdump to avoid detection based on System paths.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 201 and (ImageName = "procdump.exe" or ImageName = "psloglist.exe" or ImageName = "psexec.exe" or ImageName = "livekd.exe" or ImageName = "ADExplorer.exe"))
