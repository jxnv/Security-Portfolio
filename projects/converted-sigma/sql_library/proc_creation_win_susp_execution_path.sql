-- Title: Process Execution From A Potentially Suspicious Folder
-- ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Tim Shelton
-- Date: 2019-01-16
-- Tags: attack.stealth, attack.t1036
-- Description: Detects a potentially suspicious execution from an uncommon folder.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%:\\Perflogs\\%' OR Image ILIKE '%:\\Users\\All Users\\%' OR Image ILIKE '%:\\Users\\Default\\%' OR Image ILIKE '%:\\Users\\NetworkService\\%' OR Image ILIKE '%:\\Windows\\addins\\%' OR Image ILIKE '%:\\Windows\\debug\\%' OR Image ILIKE '%:\\Windows\\Fonts\\%' OR Image ILIKE '%:\\Windows\\Help\\%' OR Image ILIKE '%:\\Windows\\IME\\%' OR Image ILIKE '%:\\Windows\\Media\\%' OR Image ILIKE '%:\\Windows\\repair\\%' OR Image ILIKE '%:\\Windows\\security\\%' OR Image ILIKE '%:\\Windows\\System32\\Tasks\\%' OR Image ILIKE '%:\\Windows\\Tasks\\%' OR Image ILIKE '%$Recycle.bin%' OR Image ILIKE '%\\config\\systemprofile\\%' OR Image ILIKE '%\\Intel\\Logs\\%' OR Image ILIKE '%\\RSA\\MachineKeys\\%')) AND NOT (((Image ILIKE 'C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\%' AND Image ILIKE '%\\CitrixReceiverUpdater.exe') OR (Image ILIKE 'C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\%'))))
