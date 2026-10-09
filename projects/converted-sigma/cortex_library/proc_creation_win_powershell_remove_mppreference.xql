// Title: Tamper Windows Defender Remove-MpPreference
// ID: 07e3cb2c-0608-410d-be4b-1511cb1a0448
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-05
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Remove-MpPreference") and ((action_process_image_command_line contains "-ControlledFolderAccessProtectedFolders " or action_process_image_command_line contains "-AttackSurfaceReductionRules_Ids " or action_process_image_command_line contains "-AttackSurfaceReductionRules_Actions " or action_process_image_command_line contains "-CheckForSignaturesBeforeRunningScan ")))
