// Title: Rundll32 InstallScreenSaver Execution
// ID: 15bd98ea-55f4-4d37-b09a-e7caa0fa2221
// Status: test
// Level: medium
// Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io, TactiKoolSec
// Date: 2022-04-28
// Tags: attack.stealth, attack.t1218.011
// Description: An attacker may execute an application as a SCR File using rundll32.exe desk.cpl,InstallScreenSaver
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "InstallScreenSaver") and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
