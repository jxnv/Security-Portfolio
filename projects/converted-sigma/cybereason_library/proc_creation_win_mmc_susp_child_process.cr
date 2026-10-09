// Title: MMC Spawning Windows Shell
// ID: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
// Status: test
// Level: high
// Author: Karneades, Swisscom CSIRT
// Date: 2019-08-05
// Tags: attack.lateral-movement, attack.t1021.003
// Description: Detects a Windows command line executable started from MMC
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\mmc.exe") AND (((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe")) OR (Image contains "\\BITSADMIN")))
