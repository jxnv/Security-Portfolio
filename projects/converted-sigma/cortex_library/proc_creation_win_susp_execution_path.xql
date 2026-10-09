// Title: Process Execution From A Potentially Suspicious Folder
// ID: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Tim Shelton
// Date: 2019-01-16
// Tags: attack.stealth, attack.t1036
// Description: Detects a potentially suspicious execution from an uncommon folder.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path contains ":\\Perflogs\\" or action_process_image_path contains ":\\Users\\All Users\\" or action_process_image_path contains ":\\Users\\Default\\" or action_process_image_path contains ":\\Users\\NetworkService\\" or action_process_image_path contains ":\\Windows\\addins\\" or action_process_image_path contains ":\\Windows\\debug\\" or action_process_image_path contains ":\\Windows\\Fonts\\" or action_process_image_path contains ":\\Windows\\Help\\" or action_process_image_path contains ":\\Windows\\IME\\" or action_process_image_path contains ":\\Windows\\Media\\" or action_process_image_path contains ":\\Windows\\repair\\" or action_process_image_path contains ":\\Windows\\security\\" or action_process_image_path contains ":\\Windows\\System32\\Tasks\\" or action_process_image_path contains ":\\Windows\\Tasks\\" or action_process_image_path contains "$Recycle.bin" or action_process_image_path contains "\\config\\systemprofile\\" or action_process_image_path contains "\\Intel\\Logs\\" or action_process_image_path contains "\\RSA\\MachineKeys\\")) and not (((action_process_image_path startswith "C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\" and action_process_image_path endswith "\\CitrixReceiverUpdater.exe") or (action_process_image_path startswith "C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\"))))
