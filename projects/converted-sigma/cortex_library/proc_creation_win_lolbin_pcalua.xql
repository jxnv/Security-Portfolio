// Title: Use of Pcalua For Execution
// ID: 0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2022-06-14
// Tags: attack.execution, attack.t1059
// Description: Detects execition of commands and binaries from the context of The program compatibility assistant (Pcalua.exe). This can be used as a LOLBIN in order to bypass application whitelisting.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\pcalua.exe" and action_process_image_command_line contains " -a")
