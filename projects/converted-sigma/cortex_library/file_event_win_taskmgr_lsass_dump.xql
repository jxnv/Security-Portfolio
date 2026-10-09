// Title: LSASS Process Memory Dump Creation Via Taskmgr.EXE
// ID: 69ca12af-119d-44ed-b50f-a47af0ebc364
// Status: test
// Level: high
// Author: Swachchhanda Shrawan Poudel
// Date: 2023-10-19
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the creation of an "lsass.dmp" file by the taskmgr process. This indicates a manual dumping of the LSASS.exe process memory using Windows Task Manager.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith ":\\Windows\\system32\\taskmgr.exe" or action_process_image_path endswith ":\\Windows\\SysWOW64\\taskmgr.exe") and (action_file_path contains "\\AppData\\Local\\Temp\\" and action_file_path contains "\\lsass" and action_file_path contains ".DMP"))
