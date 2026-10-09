// Title: Bypass UAC via WSReset.exe
// ID: d797268e-28a9-49a7-b9a8-2f5039011c5c
// Status: test
// Level: high
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community, Florian Roth
// Date: 2019-10-24
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\wsreset.exe") and not (((action_process_image_path endswith "\\conhost.exe") or (action_process_image_name = "CONHOST.EXE"))))
