-- Title: Remote Thread Creation In Uncommon Target Image
-- ID: a1a144b7-5c9b-4853-a559-2172be8d4a03
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-16
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055.003
-- Description: Detects uncommon target processes for remote thread creation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetImage ILIKE '%\\calc.exe' OR TargetImage ILIKE '%\\calculator.exe' OR TargetImage ILIKE '%\\mspaint.exe' OR TargetImage ILIKE '%\\notepad.exe' OR TargetImage ILIKE '%\\ping.exe' OR TargetImage ILIKE '%\\sethc.exe' OR TargetImage ILIKE '%\\spoolsv.exe' OR TargetImage ILIKE '%\\wordpad.exe' OR TargetImage ILIKE '%\\write.exe')) AND NOT (((SourceImage = 'C:\\Windows\\System32\\csrss.exe') OR ((SourceImage = 'C:\\Windows\\System32\\explorer.exe' OR SourceImage = 'C:\\Windows\\System32\\OpenWith.exe') AND TargetImage = 'C:\\Windows\\System32\\notepad.exe') OR (SourceImage = 'C:\\Windows\\System32\\AtBroker.exe' AND TargetImage = 'C:\\Windows\\System32\\Sethc.exe'))) AND NOT (((StartFunction = 'EtwpNotificationThread') OR (SourceImage ILIKE '%unknown process%') OR (SourceImage = 'C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe' AND StartFunction = 'GetCommandLineW' AND (TargetImage = 'C:\\Windows\\System32\\notepad.exe' OR TargetImage = 'C:\\Windows\\System32\\spoolsv.exe')) OR (SourceImage = 'C:\\Program Files\\Xerox\\XeroxPrintExperience\\CommonFiles\\XeroxPrintJobEventManagerService.exe' AND StartFunction = 'LoadLibraryW' AND TargetImage = 'C:\\Windows\\System32\\spoolsv.exe'))))
