// Title: Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE
// ID: d2451be2-b582-4e15-8701-4196ac180260
// Status: test
// Level: high
// Author: Swachchhanda Shrawan Poudel
// Date: 2024-04-15
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects potential DLL side loading of "KeyScramblerIE.dll" by "KeyScrambler.exe".
// Various threat actors and malware have been found side loading a masqueraded "KeyScramblerIE.dll" through "KeyScrambler.exe".
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\KeyScrambler.exe" OR Image="*\\KeyScramblerLogon.exe") AND ImageLoaded="*\\KeyScramblerIE.dll") AND NOT ((((Image contains "C:\\Program Files (x86)\\KeyScrambler\\" OR Image contains "C:\\Program Files\\KeyScrambler\\") AND (ImageLoaded contains "C:\\Program Files (x86)\\KeyScrambler\\" OR ImageLoaded contains "C:\\Program Files\\KeyScrambler\\")) OR (Signature == "QFX Software Corporation" AND SignatureStatus == "Valid"))))
