// Title: VHD Image Download Via Browser
// ID: 8468111a-ef07-4654-903b-b863a80bbc95
// Status: test
// Level: medium
// Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
// Date: 2021-10-25
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects creation of ".vhd"/".vhdx" files by browser processes.
// Malware can use mountable Virtual Hard Disk ".vhd" files to encapsulate payloads and evade security controls.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\firefox.exe" or action_process_image_path endswith "\\iexplore.exe" or action_process_image_path endswith "\\maxthon.exe" or action_process_image_path endswith "\\MicrosoftEdge.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\msedgewebview2.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\safari.exe" or action_process_image_path endswith "\\seamonkey.exe" or action_process_image_path endswith "\\vivaldi.exe" or action_process_image_path endswith "\\whale.exe") and action_file_path contains ".vhd")
