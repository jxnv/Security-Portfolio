// Title: Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE
// ID: a35f5a72-f347-4e36-8895-9869b0d5fc6d
// Status: test
// Level: high
// Author: Sander Wiebing, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
// Date: 2020-05-25
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects Netsh command execution that whitelists a program located in a suspicious location in the Windows Firewall
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "*firewall*" AND CommandLine: "*add*" AND CommandLine: "*allowedprogram*")) OR ((CommandLine: "*advfirewall*" AND CommandLine: "*firewall*" AND CommandLine: "*add*" AND CommandLine: "*rule*" AND CommandLine: "*action=allow*" AND CommandLine: "*program=*"))) AND ((Image="*\\netsh.exe") OR (OriginalFileName: "netsh.exe")) AND ((CommandLine: "*:\\$Recycle.bin\\*" OR CommandLine: "*:\\RECYCLER.BIN\\*" OR CommandLine: "*:\\RECYCLERS.BIN\\*" OR CommandLine: "*:\\SystemVolumeInformation\\*" OR CommandLine: "*:\\Temp\\*" OR CommandLine: "*:\\Users\\Default\\*" OR CommandLine: "*:\\Users\\Desktop\\*" OR CommandLine: "*:\\Users\\Public\\*" OR CommandLine: "*:\\Windows\\addins\\*" OR CommandLine: "*:\\Windows\\cursors\\*" OR CommandLine: "*:\\Windows\\debug\\*" OR CommandLine: "*:\\Windows\\drivers\\*" OR CommandLine: "*:\\Windows\\fonts\\*" OR CommandLine: "*:\\Windows\\help\\*" OR CommandLine: "*:\\Windows\\system32\\tasks\\*" OR CommandLine: "*:\\Windows\\Tasks\\*" OR CommandLine: "*:\\Windows\\Temp\\*" OR CommandLine: "*\\Downloads\\*" OR CommandLine: "*\\Local Settings\\Temporary Internet Files\\*" OR CommandLine: "*\\Temporary Internet Files\\Content.Outlook\\*" OR CommandLine: "*%Public%\\*" OR CommandLine: "*%TEMP%*" OR CommandLine: "*%TMP%*")))
