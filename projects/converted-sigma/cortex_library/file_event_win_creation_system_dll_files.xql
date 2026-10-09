// Title: Files With System DLL Name In Unsuspected Locations
// ID: 13c02350-4177-4e45-ac17-cf7ca628ff5e
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-06-24
// Tags: attack.stealth, attack.t1036.005
// Description: Detects the creation of a file with the ".dll" extension that has the name of a System DLL in uncommon or unsuspected locations. (Outisde of "System32", "SysWOW64", etc.).
// It is highly recommended to perform an initial baseline before using this rule in production.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\secur32.dll" or action_file_path endswith "\\tdh.dll")) and not (((action_file_path contains "C:\\$WINDOWS.~BT\\" or action_file_path contains "C:\\$WinREAgent\\" or action_file_path contains "C:\\Windows\\SoftwareDistribution\\" or action_file_path contains "C:\\Windows\\System32\\" or action_file_path contains "C:\\Windows\\SysWOW64\\" or action_file_path contains "C:\\Windows\\WinSxS\\" or action_file_path contains "C:\\Windows\\uus\\"))))
