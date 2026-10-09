// Title: Registry Export of Third-Party Credentials
// ID: cc1abf27-78a3-4ac5-a51c-f3070b1d8e40
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-05-22
// Tags: attack.credential-access, attack.t1552.002
// Description: Detects the use of reg.exe to export registry paths associated with third-party credentials.
// Credential stealers have been known to use this technique to extract sensitive information from the registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\Software\\Aerofox\\Foxmail\\V3.1" or action_process_image_command_line contains "\\Software\\Aerofox\\FoxmailPreview" or action_process_image_command_line contains "\\Software\\DownloadManager\\Passwords" or action_process_image_command_line contains "\\Software\\FTPWare\\COREFTP\\Sites" or action_process_image_command_line contains "\\Software\\IncrediMail\\Identities" or action_process_image_command_line contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" or action_process_image_command_line contains "\\Software\\Mobatek\\MobaXterm" or action_process_image_command_line contains "\\Software\\OpenSSH\\Agent\\Keys" or action_process_image_command_line contains "\\Software\\OpenVPN-GUI\\configs" or action_process_image_command_line contains "\\Software\\ORL\\WinVNC3\\Password" or action_process_image_command_line contains "\\Software\\Qualcomm\\Eudora\\CommandLine" or action_process_image_command_line contains "\\Software\\RealVNC\\WinVNC4" or action_process_image_command_line contains "\\Software\\RimArts\\B2\\Settings" or action_process_image_command_line contains "\\Software\\SimonTatham\\PuTTY\\Sessions" or action_process_image_command_line contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys" or action_process_image_command_line contains "\\Software\\Sota\\FFFTP" or action_process_image_command_line contains "\\Software\\TightVNC\\Server" or action_process_image_command_line contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin")) and ((action_process_image_command_line contains "save" or action_process_image_command_line contains "export")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))
