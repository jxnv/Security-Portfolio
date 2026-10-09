// Title: Dumping Process via Sqldumper.exe
// ID: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
// Status: test
// Level: medium
// Author: Kirill Kiryanov, oscd.community
// Date: 2020-10-08
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects process dump via legitimate sqldumper.exe binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\sqldumper.exe" and (action_process_image_command_line contains "0x0110" or action_process_image_command_line contains "0x01100:40"))
