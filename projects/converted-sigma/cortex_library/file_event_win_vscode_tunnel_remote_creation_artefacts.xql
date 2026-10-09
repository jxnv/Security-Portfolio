// Title: Visual Studio Code Tunnel Remote File Creation
// ID: 56e05d41-ce99-4ecd-912d-93f019ee0b71
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-10-25
// Tags: attack.command-and-control
// Description: Detects the creation of file by the "node.exe" process in the ".vscode-server" directory. Could be a sign of remote file creation via VsCode tunnel feature
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path contains "\\servers\\Stable-" and action_process_image_path endswith "\\server\\node.exe" and action_file_path contains "\\.vscode-server\\data\\User\\History\\")
