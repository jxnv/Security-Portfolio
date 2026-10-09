// Title: Potential Arbitrary File Download Using Office Application
// ID: 4ae3e30b-b03f-43aa-87e3-b622f4048eed
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
// Date: 2022-05-17
// Tags: attack.stealth, attack.t1202
// Description: Detects potential arbitrary file download using a Microsoft Office application
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://")) and (((action_process_image_path endswith "\\EXCEL.EXE" or action_process_image_path endswith "\\MSOXMLED.EXE" or action_process_image_path endswith "\\POWERPNT.EXE" or action_process_image_path endswith "\\WINWORD.exe")) or ((action_process_image_name = "Excel.exe" or action_process_image_name = "msoxmled.exe" or action_process_image_name = "POWERPNT.EXE" or action_process_image_name = "WinWord.exe"))))
