// Title: Suspicious Process Start Locations
// ID: 15b75071-74cc-47e0-b4c6-b43744a62a2b
// Status: test
// Level: medium
// Author: juju4, Jonhnathan Ribeiro, oscd.community
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1036, car.2013-05-002
// Description: Detects suspicious process run from unusual locations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path contains ":\\RECYCLER\\" or action_process_image_path contains ":\\SystemVolumeInformation\\")) or ((action_process_image_path startswith "C:\\Windows\\Tasks\\" or action_process_image_path startswith "C:\\Windows\\debug\\" or action_process_image_path startswith "C:\\Windows\\fonts\\" or action_process_image_path startswith "C:\\Windows\\help\\" or action_process_image_path startswith "C:\\Windows\\drivers\\" or action_process_image_path startswith "C:\\Windows\\addins\\" or action_process_image_path startswith "C:\\Windows\\cursors\\" or action_process_image_path startswith "C:\\Windows\\system32\\tasks\\")))
