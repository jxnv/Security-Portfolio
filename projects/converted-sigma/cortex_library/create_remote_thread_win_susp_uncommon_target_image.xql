// Title: Remote Thread Creation In Uncommon Target Image
// ID: a1a144b7-5c9b-4853-a559-2172be8d4a03
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-16
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055.003
// Description: Detects uncommon target processes for remote thread creation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetImage endswith "\\calc.exe" or TargetImage endswith "\\calculator.exe" or TargetImage endswith "\\mspaint.exe" or TargetImage endswith "\\notepad.exe" or TargetImage endswith "\\ping.exe" or TargetImage endswith "\\sethc.exe" or TargetImage endswith "\\spoolsv.exe" or TargetImage endswith "\\wordpad.exe" or TargetImage endswith "\\write.exe")) and not (((SourceImage = "C:\\Windows\\System32\\csrss.exe") or ((SourceImage = "C:\\Windows\\System32\\explorer.exe" or SourceImage = "C:\\Windows\\System32\\OpenWith.exe") and TargetImage = "C:\\Windows\\System32\\notepad.exe") or (SourceImage = "C:\\Windows\\System32\\AtBroker.exe" and TargetImage = "C:\\Windows\\System32\\Sethc.exe"))) and not (((StartFunction = "EtwpNotificationThread") or (SourceImage contains "unknown process") or (SourceImage = "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" and StartFunction = "GetCommandLineW" and (TargetImage = "C:\\Windows\\System32\\notepad.exe" or TargetImage = "C:\\Windows\\System32\\spoolsv.exe")) or (SourceImage = "C:\\Program Files\\Xerox\\XeroxPrintExperience\\CommonFiles\\XeroxPrintJobEventManagerService.exe" and StartFunction = "LoadLibraryW" and TargetImage = "C:\\Windows\\System32\\spoolsv.exe"))))
