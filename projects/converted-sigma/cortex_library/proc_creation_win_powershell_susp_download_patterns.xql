// Title: Suspicious PowerShell Download and Execute Pattern
// ID: e6c54d94-498c-4562-a37c-b469d8e9a275
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-28
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "IEX ((New-Object Net.WebClient).DownloadString" or action_process_image_command_line contains "IEX (New-Object Net.WebClient).DownloadString" or action_process_image_command_line contains "IEX((New-Object Net.WebClient).DownloadString" or action_process_image_command_line contains "IEX(New-Object Net.WebClient).DownloadString" or action_process_image_command_line contains " -command (New-Object System.Net.WebClient).DownloadFile(" or action_process_image_command_line contains " -c (New-Object System.Net.WebClient).DownloadFile("))
