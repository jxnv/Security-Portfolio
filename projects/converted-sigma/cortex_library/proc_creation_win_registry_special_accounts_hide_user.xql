// Title: Hiding User Account Via SpecialAccounts Registry Key - CommandLine
// ID: 9ec9fb1b-e059-4489-9642-f270c207923d
// Status: test
// Level: medium
// Author: @Kostastsale, TheDFIRReport
// Date: 2022-05-14
// Tags: attack.stealth, attack.t1564.002
// Description: Detects changes to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\reg.exe" and (action_process_image_command_line contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" and action_process_image_command_line contains "add" and action_process_image_command_line contains "/v" and action_process_image_command_line contains "/d 0"))
