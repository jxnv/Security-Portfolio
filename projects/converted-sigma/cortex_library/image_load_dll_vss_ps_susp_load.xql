// Title: Suspicious Volume Shadow Copy VSS_PS.dll Load
// ID: 333cdbe8-27bb-4246-bf82-b41a0dca4b70
// Status: test
// Level: high
// Author: Markus Neis, @markus_neis
// Date: 2021-07-07
// Tags: attack.impact, attack.t1490
// Description: Detects the image load of vss_ps.dll by uncommon executables. This DLL is used by the Volume Shadow Copy Service (VSS) to manage shadow copies of files and volumes.
// It is often abused by attackers to delete or manipulate shadow copies, which can hinder forensic investigations and data recovery efforts.
// The fact that it is loaded by processes that are not typically associated with VSS operations can indicate suspicious activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ImageLoaded endswith "\\vss_ps.dll") and not (((action_process_image_path = null) or (action_process_image_path startswith "C:\\Windows\\" and (action_process_image_path endswith "\\clussvc.exe" or action_process_image_path endswith "\\dismhost.exe" or action_process_image_path endswith "\\dllhost.exe" or action_process_image_path endswith "\\inetsrv\\appcmd.exe" or action_process_image_path endswith "\\inetsrv\\iissetup.exe" or action_process_image_path endswith "\\msiexec.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\searchindexer.exe" or action_process_image_path endswith "\\srtasks.exe" or action_process_image_path endswith "\\svchost.exe" or action_process_image_path endswith "\\System32\\SystemPropertiesAdvanced.exe" or action_process_image_path endswith "\\taskhostw.exe" or action_process_image_path endswith "\\thor.exe" or action_process_image_path endswith "\\thor64.exe" or action_process_image_path endswith "\\tiworker.exe" or action_process_image_path endswith "\\vssvc.exe" or action_process_image_path endswith "\\vssadmin.exe" or action_process_image_path endswith "\\WmiPrvSE.exe" or action_process_image_path endswith "\\wsmprovhost.exe")) or (action_process_image_command_line startswith "C:\\$WinREAgent\\Scratch\\" and action_process_image_command_line contains "\\dismhost.exe {"))) and not (((action_process_image_path startswith "C:\\Program Files\\" or action_process_image_path startswith "C:\\Program Files (x86)\\"))))
