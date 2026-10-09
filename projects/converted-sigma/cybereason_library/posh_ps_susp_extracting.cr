// Title: Extracting Information with PowerShell
// ID: bd5971a7-626d-46ab-8176-ed643f694f68
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-19
// Tags: attack.credential-access, attack.t1552.001
// Description: Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.
// These can be files created by users to store their own credentials, shared credential stores for a group of individuals,
// configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "ls" AND ScriptBlockText contains " -R" AND ScriptBlockText contains "select-string " AND ScriptBlockText contains "-Pattern "))
