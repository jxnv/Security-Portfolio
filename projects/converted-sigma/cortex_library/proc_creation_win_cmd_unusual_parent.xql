// Title: Unusual Parent Process For Cmd.EXE
// ID: 4b991083-3d0e-44ce-8fc4-b254025d8d4b
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-21
// Tags: attack.execution, attack.t1059
// Description: Detects suspicious parent process for cmd.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\cmd.exe" and (actor_process_image_path endswith "\\csrss.exe" or actor_process_image_path endswith "\\ctfmon.exe" or actor_process_image_path endswith "\\dllhost.exe" or actor_process_image_path endswith "\\epad.exe" or actor_process_image_path endswith "\\FlashPlayerUpdateService.exe" or actor_process_image_path endswith "\\GoogleUpdate.exe" or actor_process_image_path endswith "\\jucheck.exe" or actor_process_image_path endswith "\\jusched.exe" or actor_process_image_path endswith "\\LogonUI.exe" or actor_process_image_path endswith "\\lsass.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\SearchIndexer.exe" or actor_process_image_path endswith "\\SearchProtocolHost.exe" or actor_process_image_path endswith "\\SIHClient.exe" or actor_process_image_path endswith "\\sihost.exe" or actor_process_image_path endswith "\\slui.exe" or actor_process_image_path endswith "\\spoolsv.exe" or actor_process_image_path endswith "\\sppsvc.exe" or actor_process_image_path endswith "\\taskhostw.exe" or actor_process_image_path endswith "\\unsecapp.exe" or actor_process_image_path endswith "\\WerFault.exe" or actor_process_image_path endswith "\\wermgr.exe" or actor_process_image_path endswith "\\wlanext.exe" or actor_process_image_path endswith "\\WUDFHost.exe"))
