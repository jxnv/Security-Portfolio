// Title: Process Execution From A Potentially Suspicious Folder
// ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Tim Shelton
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1036
// Description: Detects a potentially suspicious execution from an uncommon folder.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image contains ":\\Perflogs\\" OR Image contains ":\\Users\\All Users\\" OR Image contains ":\\Users\\Default\\" OR Image contains ":\\Users\\NetworkService\\" OR Image contains ":\\Windows\\addins\\" OR Image contains ":\\Windows\\debug\\" OR Image contains ":\\Windows\\Fonts\\" OR Image contains ":\\Windows\\Help\\" OR Image contains ":\\Windows\\IME\\" OR Image contains ":\\Windows\\Media\\" OR Image contains ":\\Windows\\repair\\" OR Image contains ":\\Windows\\security\\" OR Image contains ":\\Windows\\System32\\Tasks\\" OR Image contains ":\\Windows\\Tasks\\" OR Image contains "$Recycle.bin" OR Image contains "\\config\\systemprofile\\" OR Image contains "\\Intel\\Logs\\" OR Image contains "\\RSA\\MachineKeys\\")) AND NOT (((Image="C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\*" AND Image="*\\CitrixReceiverUpdater.exe") OR (Image="C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\*"))))
