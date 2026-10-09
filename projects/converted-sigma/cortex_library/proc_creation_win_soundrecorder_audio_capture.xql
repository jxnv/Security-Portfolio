// Title: Audio Capture via SoundRecorder
// ID: 83865853-59aa-449e-9600-74b9d89a6d6e
// Status: test
// Level: medium
// Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
// Date: 2019-10-24
// Tags: attack.collection, attack.t1123
// Description: Detect attacker collecting audio via SoundRecorder application.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\SoundRecorder.exe" and action_process_image_command_line contains "/FILE")
