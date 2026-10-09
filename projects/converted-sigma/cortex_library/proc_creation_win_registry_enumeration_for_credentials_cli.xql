// Title: Enumeration for 3rd Party Creds From CLI
// ID: 87a476dc-0079-4583-a985-dee7a20a03de
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.credential-access, attack.t1552.002
// Description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\Software\\Aerofox\\Foxmail\\V3.1" or action_process_image_command_line contains "\\Software\\Aerofox\\FoxmailPreview" or action_process_image_command_line contains "\\Software\\DownloadManager\\Passwords" or action_process_image_command_line contains "\\Software\\FTPWare\\COREFTP\\Sites" or action_process_image_command_line contains "\\Software\\IncrediMail\\Identities" or action_process_image_command_line contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" or action_process_image_command_line contains "\\Software\\Mobatek\\MobaXterm\\" or action_process_image_command_line contains "\\Software\\OpenSSH\\Agent\\Keys" or action_process_image_command_line contains "\\Software\\OpenVPN-GUI\\configs" or action_process_image_command_line contains "\\Software\\ORL\\WinVNC3\\Password" or action_process_image_command_line contains "\\Software\\Qualcomm\\Eudora\\CommandLine" or action_process_image_command_line contains "\\Software\\RealVNC\\WinVNC4" or action_process_image_command_line contains "\\Software\\RimArts\\B2\\Settings" or action_process_image_command_line contains "\\Software\\SimonTatham\\PuTTY\\Sessions" or action_process_image_command_line contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\" or action_process_image_command_line contains "\\Software\\Sota\\FFFTP" or action_process_image_command_line contains "\\Software\\TightVNC\\Server" or action_process_image_command_line contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin")) and not ((action_process_image_path endswith "reg.exe" and (action_process_image_command_line contains "export" or action_process_image_command_line contains "save"))))
