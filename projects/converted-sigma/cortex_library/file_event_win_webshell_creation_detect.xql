// Title: Potential Webshell Creation On Static Website
// ID: 39f1f9f2-9636-45de-98f6-a4046aa8e4b9
// Status: test
// Level: medium
// Author: Beyu Denis, oscd.community, Tim Shelton, Thurein Oo
// Date: 2019-10-22
// Tags: attack.persistence, attack.t1505.003
// Description: Detects the creation of files with certain extensions on a static web site. This can be indicative of potential uploads of a web shell.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_file_path contains ".ashx" or action_file_path contains ".asp" or action_file_path contains ".ph" or action_file_path contains ".soap")) and (action_file_path contains "\\inetpub\\wwwroot\\")) or ((action_file_path contains ".ph") and ((action_file_path contains "\\www\\" or action_file_path contains "\\htdocs\\" or action_file_path contains "\\html\\")))) and not (((action_file_path contains "\\xampp") or (action_process_image_path = "System") or ((action_file_path contains "\\AppData\\Local\\Temp\\" or action_file_path contains "\\Windows\\Temp\\")))))
