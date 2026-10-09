// Title: Create Volume Shadow Copy with Powershell
// ID: afd12fed-b0ec-45c9-a13d-aa86625dac81
// Status: test
// Level: high
// Author: frack113
// Date: 2022-01-12
// Tags: attack.credential-access, attack.t1003.003, attack.ds0005
// Description: Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Win32_ShadowCopy" AND ScriptBlockText contains ").Create(" AND ScriptBlockText contains "ClientAccessible"))
