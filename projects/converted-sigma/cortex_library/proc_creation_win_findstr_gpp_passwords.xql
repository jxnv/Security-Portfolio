// Title: Findstr GPP Passwords
// ID: 91a2c315-9ee6-4052-a853-6f6a8238f90d
// Status: test
// Level: high
// Author: frack113
// Date: 2021-12-27
// Tags: attack.credential-access, attack.t1552.006
// Description: Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "cpassword" and action_process_image_command_line contains "\\sysvol\\" and action_process_image_command_line contains ".xml")) and (((action_process_image_path endswith "\\find.exe" or action_process_image_path endswith "\\findstr.exe")) or ((action_process_image_name = "FIND.EXE" or action_process_image_name = "FINDSTR.EXE"))))
