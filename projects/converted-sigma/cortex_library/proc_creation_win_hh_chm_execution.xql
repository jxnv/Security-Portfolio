// Title: HH.EXE Execution
// ID: 68c8acb4-1b60-4890-8e82-3ddf7a6dba84
// Status: test
// Level: low
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Dan Beavin), oscd.community
// Date: 2019-10-24
// Tags: attack.stealth, attack.t1218.001
// Description: Detects the execution of "hh.exe" to open ".chm" files.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains ".chm") and ((action_process_image_name = "HH.exe") or (action_process_image_path endswith "\\hh.exe")))
