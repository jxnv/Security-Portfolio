// Title: Suspicious IO.FileStream
// ID: 70ad982f-67c8-40e0-a955-b920c2fa05cb
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-09
// Tags: attack.stealth, attack.t1070.003
// Description: Open a handle on the drive volume via the \\.\ DOS device path specifier and perform direct access read of the first few bytes of the volume.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*New-Object*" AND ScriptBlockText: "*IO.FileStream*" AND ScriptBlockText: "*\\\\\\\\.\\\\*"))
