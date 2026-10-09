// Title: Startup Folder File Write
// ID: 2aa0a6b4-a865-495b-ab51-c28249537b75
// Status: test
// Level: medium
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-05-02
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp") and not ((((action_process_image_path = "C:\\Windows\\System32\\wuauclt.exe" or action_process_image_path = "C:\\Windows\\uus\\ARM64\\wuaucltcore.exe")) or ((action_file_path startswith "C:\\$WINDOWS.~BT\\NewOS\\" or action_file_path startswith "C:\\$WinREAgent\\Scratch\\Mount\\")))) and not ((action_process_image_path endswith "\\ONENOTE.EXE" and action_file_path endswith "\\Send to OneNote.lnk")))
