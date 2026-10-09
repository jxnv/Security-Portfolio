// Title: Renamed Mavinject.EXE Execution
// ID: e6474a1b-5390-49cd-ab41-8d88655f7394
// Status: test
// Level: high
// Author: frack113, Florian Roth
// Date: 2022-12-05
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055.001, attack.t1218.013
// Description: Detects the execution of a renamed version of the "Mavinject" process. Which can be abused to perform process injection using the "/INJECTRUNNING" flag
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "mavinject32.exe" or action_process_image_name = "mavinject64.exe")) and not (((action_process_image_path endswith "\\mavinject32.exe" or action_process_image_path endswith "\\mavinject64.exe"))))
