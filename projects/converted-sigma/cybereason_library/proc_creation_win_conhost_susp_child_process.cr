// Title: Uncommon Child Process Of Conhost.EXE
// ID: 7dc2dedd-7603-461a-bc13-15803d132355
// Status: test
// Level: medium
// Author: omkar72
// Date: 2020-10-25
// Tags: attack.stealth, attack.t1202
// Description: Detects uncommon "conhost" child processes. This could be a sign of "conhost" usage as a LOLBIN or potential process injection activity.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\conhost.exe") AND NOT (((Image="*:\\Windows\\System32\\conhost.exe") OR (Image == "") OR (NOT Image=*))) AND NOT ((Provider_Name == "SystemTraceProvider-Process")))
