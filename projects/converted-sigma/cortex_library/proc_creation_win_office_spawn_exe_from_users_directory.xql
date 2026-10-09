// Title: Suspicious Binary In User Directory Spawned From Office Application
// ID: aa3a6f94-890e-4e22-b634-ffdfd54792cc
// Status: test
// Level: high
// Author: Jason Lynch
// Date: 2019-04-02
// Tags: attack.execution, attack.t1204.002, attack.g0046, car.2013-05-002
// Description: Detects an executable in the users directory started from one of the Microsoft Office suite applications (Word, Excel, PowerPoint, Publisher, Visio)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\WINWORD.EXE" or actor_process_image_path endswith "\\EXCEL.EXE" or actor_process_image_path endswith "\\POWERPNT.exe" or actor_process_image_path endswith "\\MSPUB.exe" or actor_process_image_path endswith "\\VISIO.exe" or actor_process_image_path endswith "\\MSACCESS.exe" or actor_process_image_path endswith "\\EQNEDT32.exe") and action_process_image_path startswith "C:\\users\\" and action_process_image_path endswith ".exe") and not ((action_process_image_path endswith "\\Teams.exe")))
