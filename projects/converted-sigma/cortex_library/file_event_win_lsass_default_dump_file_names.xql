// Title: LSASS Process Memory Dump Files
// ID: a5a2d357-1ab8-4675-a967-ef9990a59391
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-11-15
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\Andrew.dmp" or action_file_path endswith "\\Coredump.dmp" or action_file_path endswith "\\lsass.dmp" or action_file_path endswith "\\lsass.rar" or action_file_path endswith "\\lsass.zip" or action_file_path endswith "\\NotLSASS.zip" or action_file_path endswith "\\PPLBlade.dmp" or action_file_path endswith "\\rustive.dmp")) or ((action_file_path contains "\\lsass_2" or action_file_path contains "\\lsassdmp" or action_file_path contains "\\lsassdump")) or ((action_file_path contains "\\lsass" and action_file_path contains ".dmp")) or (action_file_path contains "SQLDmpr" and action_file_path endswith ".mdmp") or ((action_file_path contains "\\nanodump" or action_file_path contains "\\proc_") and action_file_path endswith ".dmp"))
