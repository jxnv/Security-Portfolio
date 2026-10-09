// Title: Potential Regsvr32 Commandline Flag Anomaly
// ID: b236190c-1c61-41e9-84b3-3fe03f6d76b0
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2019-07-13
// Tags: attack.stealth, attack.t1218.010
// Description: Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\regsvr32.exe" and action_process_image_command_line contains " -i:") and not ((action_process_image_command_line contains " -n ")))
