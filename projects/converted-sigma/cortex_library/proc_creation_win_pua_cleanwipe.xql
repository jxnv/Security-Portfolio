// Title: PUA - CleanWipe Execution
// ID: f44800ac-38ec-471f-936e-3fa7d9c53100
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-18
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\SepRemovalToolNative_x64.exe") or (action_process_image_path endswith "\\CATClean.exe" and action_process_image_command_line contains "--uninstall") or (action_process_image_path endswith "\\NetInstaller.exe" and action_process_image_command_line contains "-r") or (action_process_image_path endswith "\\WFPUnins.exe" and (action_process_image_command_line contains "/uninstall" and action_process_image_command_line contains "/enterprise")))
