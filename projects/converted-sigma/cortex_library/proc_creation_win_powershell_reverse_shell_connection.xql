// Title: Potential Powershell ReverseShell Connection
// ID: edc2f8ae-2412-4dfd-b9d5-0c57727e70be
// Status: stable
// Level: high
// Author: FPT.EagleEye, wagga, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-03-03
// Tags: attack.execution, attack.t1059.001
// Description: Detects usage of the "TcpClient" class. Which can be abused to establish remote connections and reverse-shells. As seen used by the Nishang "Invoke-PowerShellTcpOneLine" reverse shell and other.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " Net.Sockets.TCPClient" and action_process_image_command_line contains ".GetStream(" and action_process_image_command_line contains ".Write(")) and (((action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll")) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe"))))
