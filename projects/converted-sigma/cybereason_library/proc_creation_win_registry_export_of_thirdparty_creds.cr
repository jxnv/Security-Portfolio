// Title: Registry Export of Third-Party Credentials
// ID: cc1abf27-78a3-4ac5-a51c-f3070b1d8e40
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-05-22
// Tags: attack.credential-access, attack.t1552.002
// Description: Detects the use of reg.exe to export registry paths associated with third-party credentials.
// Credential stealers have been known to use this technique to extract sensitive information from the registry.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "\\Software\\Aerofox\\Foxmail\\V3.1" OR CommandLine contains "\\Software\\Aerofox\\FoxmailPreview" OR CommandLine contains "\\Software\\DownloadManager\\Passwords" OR CommandLine contains "\\Software\\FTPWare\\COREFTP\\Sites" OR CommandLine contains "\\Software\\IncrediMail\\Identities" OR CommandLine contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" OR CommandLine contains "\\Software\\Mobatek\\MobaXterm" OR CommandLine contains "\\Software\\OpenSSH\\Agent\\Keys" OR CommandLine contains "\\Software\\OpenVPN-GUI\\configs" OR CommandLine contains "\\Software\\ORL\\WinVNC3\\Password" OR CommandLine contains "\\Software\\Qualcomm\\Eudora\\CommandLine" OR CommandLine contains "\\Software\\RealVNC\\WinVNC4" OR CommandLine contains "\\Software\\RimArts\\B2\\Settings" OR CommandLine contains "\\Software\\SimonTatham\\PuTTY\\Sessions" OR CommandLine contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys" OR CommandLine contains "\\Software\\Sota\\FFFTP" OR CommandLine contains "\\Software\\TightVNC\\Server" OR CommandLine contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin")) AND ((CommandLine contains "save" OR CommandLine contains "export")) AND ((Image="*\\reg.exe") OR (OriginalFileName == "reg.exe")))
