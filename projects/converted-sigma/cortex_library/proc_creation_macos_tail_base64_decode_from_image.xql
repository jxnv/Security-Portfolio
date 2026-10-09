// Title: Potential Base64 Decoded From Images
// ID: 09a910bf-f71f-4737-9c40-88880ba5913d
// Status: test
// Level: high
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-12-20
// Tags: attack.stealth, attack.t1140
// Description: Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "base64" and action_process_image_command_line contains "-d" and action_process_image_command_line contains ">")) and ((action_process_image_command_line contains ".avif" or action_process_image_command_line contains ".gif" or action_process_image_command_line contains ".jfif" or action_process_image_command_line contains ".jpeg" or action_process_image_command_line contains ".jpg" or action_process_image_command_line contains ".pjp" or action_process_image_command_line contains ".pjpeg" or action_process_image_command_line contains ".png" or action_process_image_command_line contains ".svg" or action_process_image_command_line contains ".webp")) and (action_process_image_path endswith "/bash") and ((action_process_image_command_line contains "tail" and action_process_image_command_line contains "-c")))
