// Title: Potential Persistence Via Powershell Search Order Hijacking - Task
// ID: b66474aa-bd92-4333-a16c-298155b120df
// Status: test
// Level: high
// Author: pH-T (Nextron Systems), Florian Roth (Nextron Systems)
// Date: 2022-04-08
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
// Description: Detects suspicious powershell execution via a schedule task where the command ends with an suspicious flags to hide the powershell instance instead of executeing scripts or commands. This could be a sign of persistence via PowerShell "Get-Variable" technique as seen being used in Colibri Loader
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path = "C:\\WINDOWS\\System32\\svchost.exe" and (actor_process_command_line contains "-k netsvcs" and actor_process_command_line contains "-s Schedule") and (action_process_image_command_line endswith " -windowstyle hidden" or action_process_image_command_line endswith " -w hidden" or action_process_image_command_line endswith " -ep bypass" or action_process_image_command_line endswith " -noni"))
