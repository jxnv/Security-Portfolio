// Title: Potential LethalHTA Technique Execution
// ID: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
// Status: test
// Level: high
// Author: Markus Neis
// Date: 2018-06-07
// Tags: attack.stealth, attack.t1218.005
// Description: Detects potential LethalHTA technique where the "mshta.exe" is spawned by an "svchost.exe" process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\svchost.exe" and action_process_image_path endswith "\\mshta.exe")
