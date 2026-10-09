// Title: Enumeration for 3rd Party Creds From CLI
// ID: 87a476dc-0079-4583-a985-dee7a20a03de
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.credential-access, attack.t1552.002
// Description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "\\Software\\Aerofox\\Foxmail\\V3.1" OR CommandLine contains "\\Software\\Aerofox\\FoxmailPreview" OR CommandLine contains "\\Software\\DownloadManager\\Passwords" OR CommandLine contains "\\Software\\FTPWare\\COREFTP\\Sites" OR CommandLine contains "\\Software\\IncrediMail\\Identities" OR CommandLine contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" OR CommandLine contains "\\Software\\Mobatek\\MobaXterm\\" OR CommandLine contains "\\Software\\OpenSSH\\Agent\\Keys" OR CommandLine contains "\\Software\\OpenVPN-GUI\\configs" OR CommandLine contains "\\Software\\ORL\\WinVNC3\\Password" OR CommandLine contains "\\Software\\Qualcomm\\Eudora\\CommandLine" OR CommandLine contains "\\Software\\RealVNC\\WinVNC4" OR CommandLine contains "\\Software\\RimArts\\B2\\Settings" OR CommandLine contains "\\Software\\SimonTatham\\PuTTY\\Sessions" OR CommandLine contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\" OR CommandLine contains "\\Software\\Sota\\FFFTP" OR CommandLine contains "\\Software\\TightVNC\\Server" OR CommandLine contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin")) AND NOT ((Image="*reg.exe" AND (CommandLine contains "export" OR CommandLine contains "save"))))
