// Title: Suspicious Network Command
// ID: a29c1813-ab1f-4dde-b489-330b952e91ae
// Status: test
// Level: low
// Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
// Date: 2021-12-07
// Tags: attack.discovery, attack.t1016
// Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line ~= "ipconfig\\s+/all" or action_process_image_command_line ~= "netsh\\s+interface show interface" or action_process_image_command_line ~= "arp\\s+-a" or action_process_image_command_line ~= "nbtstat\\s+-n" or action_process_image_command_line ~= "net\\s+config" or action_process_image_command_line ~= "route\\s+print"))
