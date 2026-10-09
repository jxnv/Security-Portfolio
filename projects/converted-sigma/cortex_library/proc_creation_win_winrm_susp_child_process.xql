// Title: Suspicious Processes Spawned by WinRM
// ID: 5cc2cda8-f261-4d88-a2de-e9e193c86716
// Status: test
// Level: high
// Author: Andreas Hunkeler (@Karneades), Markus Neis
// Date: 2021-05-20
// Tags: attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious processes including shells spawnd from WinRM host process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\wsmprovhost.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\wsl.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\bitsadmin.exe"))
