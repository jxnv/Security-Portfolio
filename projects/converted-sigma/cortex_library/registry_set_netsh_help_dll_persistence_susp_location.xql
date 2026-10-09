// Title: New Netsh Helper DLL Registered From A Suspicious Location
// ID: e7b18879-676e-4a0e-ae18-27039185a8e7
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-11-28
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.007
// Description: Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\Microsoft\\NetSh") and (((Details contains ":\\Perflogs\\" or Details contains ":\\Users\\Public\\" or Details contains ":\\Windows\\Temp\\" or Details contains "\\AppData\\Local\\Temp\\" or Details contains "\\Temporary Internet")) or (((Details contains ":\\Users\\" and Details contains "\\Favorites\\")) or ((Details contains ":\\Users\\" and Details contains "\\Favourites\\")) or ((Details contains ":\\Users\\" and Details contains "\\Contacts\\")) or ((Details contains ":\\Users\\" and Details contains "\\Pictures\\")))))
