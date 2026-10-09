// Title: Renamed Office Binary Execution
// ID: 0b0cd537-fc77-4e6e-a973-e53495c1083d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-20
// Tags: attack.stealth, attack.t1036.003
// Description: Detects the execution of a renamed office binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_name = "Excel.exe" or action_process_image_name = "MSACCESS.EXE" or action_process_image_name = "MSPUB.EXE" or action_process_image_name = "OneNote.exe" or action_process_image_name = "OneNoteM.exe" or action_process_image_name = "OUTLOOK.EXE" or action_process_image_name = "POWERPNT.EXE" or action_process_image_name = "WinWord.exe" or action_process_image_name = "Olk.exe")) or ((Description = "Microsoft Access" or Description = "Microsoft Excel" or Description = "Microsoft OneNote" or Description = "Microsoft Outlook" or Description = "Microsoft PowerPoint" or Description = "Microsoft Publisher" or Description = "Microsoft Word" or Description = "Sent to OneNote Tool"))) and not (((action_process_image_path endswith "\\EXCEL.exe" or action_process_image_path endswith "\\excelcnv.exe" or action_process_image_path endswith "\\MSACCESS.exe" or action_process_image_path endswith "\\MSPUB.EXE" or action_process_image_path endswith "\\ONENOTE.EXE" or action_process_image_path endswith "\\ONENOTEM.EXE" or action_process_image_path endswith "\\OUTLOOK.EXE" or action_process_image_path endswith "\\POWERPNT.EXE" or action_process_image_path endswith "\\WINWORD.exe" or action_process_image_path endswith "\\OLK.EXE"))))
