// Title: NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE
// ID: ebef4391-1a81-4761-a40a-1db446c0e625
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-06-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.003
// Description: Detects the attempt to create an ActiveScriptEventConsumer via WMIC.EXE.
// An ActiveScriptEventConsumer is a built-in Windows Management Instrumentation (WMI) class that
// automatically executes a predefined script (in VBScript or JScript) whenever a specific system event occurs.
// Adversaries often abuse ActiveScriptEventConsumer to maintain persistence on a compromised host by executing a malicious script whenever a specific event occurs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "ActiveScriptEventConsumer" and action_process_image_command_line contains " CREATE ")) and ((action_process_image_name = "wmic.exe") or (action_process_image_path endswith "\\WMIC.exe")))
