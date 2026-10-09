// Title: Potential Persistence Via Microsoft Compatibility Appraiser
// ID: f548a603-c9f2-4c89-b511-b089f7e94549
// Status: test
// Level: medium
// Author: Sreeman
// Date: 2020-09-29
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Detects manual execution of the "Microsoft Compatibility Appraiser" task via schtasks.
// In order to trigger persistence stored in the "\AppCompatFlags\TelemetryController" registry key.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "run " and action_process_image_command_line contains "\\Application Experience\\Microsoft Compatibility Appraiser")) and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
