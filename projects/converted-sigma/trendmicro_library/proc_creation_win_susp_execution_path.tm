// Title: Process Execution From A Potentially Suspicious Folder
// ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Tim Shelton
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1036
// Description: Detects a potentially suspicious execution from an uncommon folder.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image: "*:\\Perflogs\\*" OR Image: "*:\\Users\\All Users\\*" OR Image: "*:\\Users\\Default\\*" OR Image: "*:\\Users\\NetworkService\\*" OR Image: "*:\\Windows\\addins\\*" OR Image: "*:\\Windows\\debug\\*" OR Image: "*:\\Windows\\Fonts\\*" OR Image: "*:\\Windows\\Help\\*" OR Image: "*:\\Windows\\IME\\*" OR Image: "*:\\Windows\\Media\\*" OR Image: "*:\\Windows\\repair\\*" OR Image: "*:\\Windows\\security\\*" OR Image: "*:\\Windows\\System32\\Tasks\\*" OR Image: "*:\\Windows\\Tasks\\*" OR Image: "*$Recycle.bin*" OR Image: "*\\config\\systemprofile\\*" OR Image: "*\\Intel\\Logs\\*" OR Image: "*\\RSA\\MachineKeys\\*")) AND NOT (((Image="C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\*" AND Image="*\\CitrixReceiverUpdater.exe") OR (Image="C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\*"))))
