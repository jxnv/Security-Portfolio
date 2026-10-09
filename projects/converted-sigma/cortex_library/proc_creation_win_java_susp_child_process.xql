// Title: Suspicious Processes Spawned by Java.EXE
// ID: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
// Status: test
// Level: high
// Author: Andreas Hunkeler (@Karneades), Florian Roth
// Date: 2021-12-17
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
// Description: Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\java.exe" and (action_process_image_path endswith "\\AppVLP.exe" or action_process_image_path endswith "\\bitsadmin.exe" or action_process_image_path endswith "\\certutil.exe" or action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\forfiles.exe" or action_process_image_path endswith "\\hh.exe" or action_process_image_path endswith "\\mftrace.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\net.exe" or action_process_image_path endswith "\\net1.exe" or action_process_image_path endswith "\\query.exe" or action_process_image_path endswith "\\reg.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\schtasks.exe" or action_process_image_path endswith "\\scrcons.exe" or action_process_image_path endswith "\\scriptrunner.exe" or action_process_image_path endswith "\\sh.exe" or action_process_image_path endswith "\\systeminfo.exe" or action_process_image_path endswith "\\whoami.exe" or action_process_image_path endswith "\\wmic.exe" or action_process_image_path endswith "\\wscript.exe"))
