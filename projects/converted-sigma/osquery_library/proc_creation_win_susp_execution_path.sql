-- Title: Process Execution From A Potentially Suspicious Folder
-- ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Tim Shelton
-- Date: 2019-01-16
-- Tags: attack.stealth, attack.t1036
-- Description: Detects a potentially suspicious execution from an uncommon folder.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image LIKE '%:\\Perflogs\\%' OR Image LIKE '%:\\Users\\All Users\\%' OR Image LIKE '%:\\Users\\Default\\%' OR Image LIKE '%:\\Users\\NetworkService\\%' OR Image LIKE '%:\\Windows\\addins\\%' OR Image LIKE '%:\\Windows\\debug\\%' OR Image LIKE '%:\\Windows\\Fonts\\%' OR Image LIKE '%:\\Windows\\Help\\%' OR Image LIKE '%:\\Windows\\IME\\%' OR Image LIKE '%:\\Windows\\Media\\%' OR Image LIKE '%:\\Windows\\repair\\%' OR Image LIKE '%:\\Windows\\security\\%' OR Image LIKE '%:\\Windows\\System32\\Tasks\\%' OR Image LIKE '%:\\Windows\\Tasks\\%' OR Image LIKE '%$Recycle.bin%' OR Image LIKE '%\\config\\systemprofile\\%' OR Image LIKE '%\\Intel\\Logs\\%' OR Image LIKE '%\\RSA\\MachineKeys\\%')) AND NOT (((Image="C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\*" AND Image="*\\CitrixReceiverUpdater.exe") OR (Image="C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\*"))))
