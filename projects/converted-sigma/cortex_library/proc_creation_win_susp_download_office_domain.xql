// Title: Suspicious Download from Office Domain
// ID: 00d49ed5-4491-4271-a8db-650a4ef6f8c1
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-27
// Tags: attack.command-and-control, attack.resource-development, attack.t1105, attack.t1608
// Description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "https://attachment.outlook.live.net/owa/" or action_process_image_command_line contains "https://onenoteonlinesync.onenote.com/onenoteonlinesync/")) and (((action_process_image_path endswith "\\curl.exe" or action_process_image_path endswith "\\wget.exe")) or ((action_process_image_command_line contains "Invoke-WebRequest" or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "curl " or action_process_image_command_line contains "wget " or action_process_image_command_line contains "Start-BitsTransfer" or action_process_image_command_line contains ".DownloadFile(" or action_process_image_command_line contains ".DownloadString("))))
