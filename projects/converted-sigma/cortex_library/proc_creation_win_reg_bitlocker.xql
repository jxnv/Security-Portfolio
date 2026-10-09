// Title: Suspicious Reg Add BitLocker
// ID: 0e0255bf-2548-47b8-9582-c0955c9283f5
// Status: test
// Level: high
// Author: frack113
// Date: 2021-11-15
// Tags: attack.impact, attack.t1486
// Description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "REG" and action_process_image_command_line contains "ADD" and action_process_image_command_line contains "\\SOFTWARE\\Policies\\Microsoft\\FVE" and action_process_image_command_line contains "/v" and action_process_image_command_line contains "/f") and (action_process_image_command_line contains "EnableBDEWithNoTPM" or action_process_image_command_line contains "UseAdvancedStartup" or action_process_image_command_line contains "UseTPM" or action_process_image_command_line contains "UseTPMKey" or action_process_image_command_line contains "UseTPMKeyPIN" or action_process_image_command_line contains "RecoveryKeyMessageSource" or action_process_image_command_line contains "UseTPMPIN" or action_process_image_command_line contains "RecoveryKeyMessage"))
