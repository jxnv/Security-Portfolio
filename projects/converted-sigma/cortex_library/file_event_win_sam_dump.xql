// Title: Potential SAM Database Dump
// ID: 4e87b8e2-2ee9-4b2a-a715-4727d297ece0
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-11
// Tags: attack.credential-access, attack.t1003.002
// Description: Detects the creation of files that look like exports of the local SAM (Security Account Manager)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\Temp\\sam" or action_file_path endswith "\\sam.sav" or action_file_path endswith "\\Intel\\sam" or action_file_path endswith "\\sam.hive" or action_file_path endswith "\\Perflogs\\sam" or action_file_path endswith "\\ProgramData\\sam" or action_file_path endswith "\\Users\\Public\\sam" or action_file_path endswith "\\AppData\\Local\\sam" or action_file_path endswith "\\AppData\\Roaming\\sam" or action_file_path endswith "_ShadowSteal.zip" or action_file_path endswith "\\Documents\\SAM.export" or action_file_path endswith ":\\sam")) or ((action_file_path contains "\\hive_sam_" or action_file_path contains "\\sam.save" or action_file_path contains "\\sam.export" or action_file_path contains "\\~reg_sam.save" or action_file_path contains "\\sam_backup" or action_file_path contains "\\sam.bck" or action_file_path contains "\\sam.backup")))
