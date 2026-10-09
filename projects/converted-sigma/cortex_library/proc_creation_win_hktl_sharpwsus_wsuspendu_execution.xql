// Title: HackTool - SharpWSUS/WSUSpendu Execution
// ID: b0ce780f-10bd-496d-9067-066d23dc3aa5
// Status: test
// Level: high
// Author: @Kostastsale, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-07
// Tags: attack.execution, attack.lateral-movement, attack.t1210
// Description: Detects the execution of SharpWSUS or WSUSpendu, utilities that allow for lateral movement through WSUS.
// Windows Server Update Services (WSUS) is a critical component of Windows systems and is frequently configured in a way that allows an attacker to circumvent internal networking limitations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -Inject ") and ((action_process_image_command_line contains " -PayloadArgs " or action_process_image_command_line contains " -PayloadFile "))) or (((action_process_image_command_line contains " approve " or action_process_image_command_line contains " create " or action_process_image_command_line contains " check " or action_process_image_command_line contains " delete ")) and ((action_process_image_command_line contains " /payload:" or action_process_image_command_line contains " /payload=" or action_process_image_command_line contains " /updateid:" or action_process_image_command_line contains " /updateid="))))
