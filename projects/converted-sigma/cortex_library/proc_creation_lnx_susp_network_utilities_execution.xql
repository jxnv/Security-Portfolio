// Title: Linux Network Service Scanning Tools Execution
// ID: 3e102cd9-a70d-4a7a-9508-403963092f31
// Status: test
// Level: low
// Author: Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure])
// Date: 2020-10-21
// Tags: attack.discovery, attack.t1046
// Description: Detects execution of network scanning and reconnaisance tools. These tools can be used for the enumeration of local or remote network services for example.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/nc" or action_process_image_path endswith "/ncat" or action_process_image_path endswith "/netcat" or action_process_image_path endswith "/socat")) and not (((action_process_image_command_line contains " --listen " or action_process_image_command_line contains " -l ")))) or ((action_process_image_path endswith "/autorecon" or action_process_image_path endswith "/hping" or action_process_image_path endswith "/hping2" or action_process_image_path endswith "/hping3" or action_process_image_path endswith "/naabu" or action_process_image_path endswith "/nmap" or action_process_image_path endswith "/nping" or action_process_image_path endswith "/telnet" or action_process_image_path endswith "/zenmap")))
