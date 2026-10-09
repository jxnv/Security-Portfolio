// Title: Curl File Upload To File Sharing Websites
// ID: e328cc73-f92a-42fb-b3fa-7c2cffda981a
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-03-29
// Tags: attack.exfiltration, attack.t1567.002
// Description: Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "0x0.st" or action_process_image_command_line contains "bashupload.com" or action_process_image_command_line contains "chunk.io" or action_process_image_command_line contains "file.io" or action_process_image_command_line contains "filebin.net" or action_process_image_command_line contains "pastebin" or action_process_image_command_line contains "send.firefox.com" or action_process_image_command_line contains "temp.sh" or action_process_image_command_line contains "transfer.sh" or action_process_image_command_line contains "ufile.io" or action_process_image_command_line contains "uploadfiles.io" or action_process_image_command_line contains "wetransfer.com" or action_process_image_command_line contains "x0.at")) and (((action_process_image_command_line contains " --form" or action_process_image_command_line contains " --upload-file" or action_process_image_command_line contains " --data" or action_process_image_command_line contains " -X POST" or action_process_image_command_line contains " --request POST ")) or ((action_process_image_command_line ~= "\\s-[FTd]\\s" or action_process_image_command_line ~= "\\s-sT\\s"))) and ((action_process_image_path endswith "\\curl.exe") or (action_process_image_name = "curl.exe")))
