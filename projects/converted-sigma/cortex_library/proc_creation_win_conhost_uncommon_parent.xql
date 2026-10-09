// Title: Conhost Spawned By Uncommon Parent Process
// ID: cbb9e3d1-2386-4e59-912e-62f1484f7a89
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-28
// Tags: attack.execution, attack.t1059
// Description: Detects when the Console Window Host (conhost.exe) process is spawned by an uncommon parent process, which could be indicative of potential code injection activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\conhost.exe" and (actor_process_image_path endswith "\\explorer.exe" or actor_process_image_path endswith "\\lsass.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\services.exe" or actor_process_image_path endswith "\\smss.exe" or actor_process_image_path endswith "\\spoolsv.exe" or actor_process_image_path endswith "\\svchost.exe" or actor_process_image_path endswith "\\userinit.exe" or actor_process_image_path endswith "\\wininit.exe" or actor_process_image_path endswith "\\winlogon.exe")) and not (((actor_process_command_line contains "-k apphost -s AppHostSvc" or actor_process_command_line contains "-k imgsvc" or actor_process_command_line contains "-k localService -p -s RemoteRegistry" or actor_process_command_line contains "-k LocalSystemNetworkRestricted -p -s NgcSvc" or actor_process_command_line contains "-k NetSvcs -p -s NcaSvc" or actor_process_command_line contains "-k netsvcs -p -s NetSetupSvc" or actor_process_command_line contains "-k netsvcs -p -s wlidsvc" or actor_process_command_line contains "-k NetworkService -p -s DoSvc" or actor_process_command_line contains "-k wsappx -p -s AppXSvc" or actor_process_command_line contains "-k wsappx -p -s ClipSVC" or actor_process_command_line contains "-k wusvcs -p -s WaaSMedicSvc"))) and not (((actor_process_command_line contains "C:\\Program Files (x86)\\Dropbox\\Client\\" or actor_process_command_line contains "C:\\Program Files\\Dropbox\\Client\\"))))
