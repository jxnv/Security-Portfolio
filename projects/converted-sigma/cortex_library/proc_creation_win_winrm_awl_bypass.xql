// Title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
// ID: 074e0ded-6ced-4ebd-8b4d-53f55908119d
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-06
// Tags: attack.stealth, attack.t1216
// Description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "winrm") and (((action_process_image_command_line contains "format:pretty" or action_process_image_command_line contains "format:\"pretty\"" or action_process_image_command_line contains "format:\"text\"" or action_process_image_command_line contains "format:text")) and not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\")))))
