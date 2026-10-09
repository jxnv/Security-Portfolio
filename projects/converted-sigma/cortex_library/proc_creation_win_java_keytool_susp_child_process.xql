// Title: Suspicious Shells Spawn by Java Utility Keytool
// ID: 90fb5e62-ca1f-4e22-b42e-cc521874c938
// Status: test
// Level: high
// Author: Andreas Hunkeler (@Karneades)
// Date: 2021-12-22
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\keytool.exe" and (action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\bash.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\scrcons.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\hh.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\scriptrunner.exe" or action_process_image_path endswith "\\mftrace.exe" or action_process_image_path endswith "\\AppVLP.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\query.exe"))
