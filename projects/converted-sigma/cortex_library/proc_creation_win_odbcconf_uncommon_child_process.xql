// Title: Uncommon Child Process Spawned By Odbcconf.EXE
// ID: 8e3c7994-131e-4ba5-b6ea-804d49113a26
// Status: test
// Level: medium
// Author: Harjot Singh @cyb3rjy0t
// Date: 2023-05-22
// Tags: attack.stealth, attack.t1218.008
// Description: Detects an uncommon child process of "odbcconf.exe" binary which normally shouldn't have any child processes.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\odbcconf.exe")
