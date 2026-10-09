// Title: HackTool - SOAPHound Execution
// ID: e92a4287-e072-4a40-9739-370c106bb750
// Status: test
// Level: high
// Author: @kostastsale
// Date: 2024-01-26
// Tags: attack.discovery, attack.t1087
// Description: Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " --buildcache " or action_process_image_command_line contains " --bhdump " or action_process_image_command_line contains " --certdump " or action_process_image_command_line contains " --dnsdump ")) and ((action_process_image_command_line contains " -c " or action_process_image_command_line contains " --cachefilename " or action_process_image_command_line contains " -o " or action_process_image_command_line contains " --outputdirectory")))
