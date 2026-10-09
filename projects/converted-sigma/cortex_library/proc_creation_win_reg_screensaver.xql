// Title: Suspicious ScreenSave Change by Reg.exe
// ID: 0fc35fc3-efe6-4898-8a37-0b233339524f
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-08-19
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.002
// Description: Adversaries may establish persistence by executing malicious content triggered by user inactivity.
// Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\reg.exe" and (action_process_image_command_line contains "HKEY_CURRENT_USER\\Control Panel\\Desktop" or action_process_image_command_line contains "HKCU\\Control Panel\\Desktop")) and (((action_process_image_command_line contains "/v ScreenSaveActive" and action_process_image_command_line contains "/t REG_SZ" and action_process_image_command_line contains "/d 1" and action_process_image_command_line contains "/f")) or ((action_process_image_command_line contains "/v ScreenSaveTimeout" and action_process_image_command_line contains "/t REG_SZ" and action_process_image_command_line contains "/d " and action_process_image_command_line contains "/f")) or ((action_process_image_command_line contains "/v ScreenSaverIsSecure" and action_process_image_command_line contains "/t REG_SZ" and action_process_image_command_line contains "/d 0" and action_process_image_command_line contains "/f")) or ((action_process_image_command_line contains "/v SCRNSAVE.EXE" and action_process_image_command_line contains "/t REG_SZ" and action_process_image_command_line contains "/d " and action_process_image_command_line contains ".scr" and action_process_image_command_line contains "/f"))))
