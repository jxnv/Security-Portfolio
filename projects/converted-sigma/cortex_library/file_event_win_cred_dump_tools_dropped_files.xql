// Title: Cred Dump Tools Dropped Files
// ID: 8fbf3271-1ef6-4e94-8210-03c2317947f6
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov, oscd.community
// Date: 2019-11-01
// Tags: attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.003, attack.t1003.004, attack.t1003.005
// Description: Files with well-known filenames (parts of credential dump software or files produced by them) creation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "\\fgdump-log" or action_file_path contains "\\kirbi" or action_file_path contains "\\pwdump" or action_file_path contains "\\pwhashes" or action_file_path contains "\\wce_ccache" or action_file_path contains "\\wce_krbtkts")) or ((action_file_path endswith "\\cachedump.exe" or action_file_path endswith "\\cachedump64.exe" or action_file_path endswith "\\DumpExt.dll" or action_file_path endswith "\\DumpSvc.exe" or action_file_path endswith "\\Dumpy.exe" or action_file_path endswith "\\fgexec.exe" or action_file_path endswith "\\lsremora.dll" or action_file_path endswith "\\lsremora64.dll" or action_file_path endswith "\\NTDS.out" or action_file_path endswith "\\procdump.exe" or action_file_path endswith "\\procdump64.exe" or action_file_path endswith "\\procdump64a.exe" or action_file_path endswith "\\pstgdump.exe" or action_file_path endswith "\\pwdump.exe" or action_file_path endswith "\\SAM.out" or action_file_path endswith "\\SECURITY.out" or action_file_path endswith "\\servpw.exe" or action_file_path endswith "\\servpw64.exe" or action_file_path endswith "\\SYSTEM.out" or action_file_path endswith "\\test.pwd" or action_file_path endswith "\\wceaux.dll")))
