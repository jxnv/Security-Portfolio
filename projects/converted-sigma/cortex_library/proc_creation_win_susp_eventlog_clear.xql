// Title: Suspicious Eventlog Clearing or Configuration Change Activity
// ID: cc36992a-4671-4f21-a91d-6c2b72a2edf5
// Status: stable
// Level: high
// Author: Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2019-09-26
// Tags: attack.defense-impairment, attack.t1685.005, attack.t1685.001, car.2016-04-002
// Description: Detects the clearing or configuration tampering of EventLog using utilities such as "wevtutil", "powershell" and "wmic".
// This technique were seen used by threat actors and ransomware strains in order to evade defenses.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_command_line contains "clear-log " or action_process_image_command_line contains " cl " or action_process_image_command_line contains "set-log " or action_process_image_command_line contains " sl " or action_process_image_command_line contains "lfn:")) and ((action_process_image_path endswith "\\wevtutil.exe") or (action_process_image_name = "wevtutil.exe"))) or ((((action_process_image_command_line contains "Clear-EventLog " or action_process_image_command_line contains "Remove-EventLog " or action_process_image_command_line contains "Limit-EventLog " or action_process_image_command_line contains "Clear-WinEvent ")) or ((action_process_image_command_line contains "Eventing.Reader.EventLogSession" and action_process_image_command_line contains "ClearLog")) or ((action_process_image_command_line contains "Diagnostics.EventLog" and action_process_image_command_line contains "Clear"))) and ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe"))) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wmic.exe") and action_process_image_command_line contains "ClearEventLog")) and not (((actor_process_image_path = "C:\\Windows\\SysWOW64\\msiexec.exe" or actor_process_image_path = "C:\\Windows\\System32\\msiexec.exe") and action_process_image_command_line contains " sl ")))
