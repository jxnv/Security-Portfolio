// Title: Suspicious WSL Binary Masquerading
// ID: 530576ee-3b62-4bce-9a03-9aac6c61788a
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-05-05
// Tags: attack.stealth, attack.t1036.005, attack.t1218
// Description: Detects execution of masqueraded wsl.exe binary.
// Attackers can rename a malicious payload to wsl.exe to masquerade as the legitimate Windows Subsystem for Linux binary,
// bypassing detection based on image name alone and abusing user trust in the WSL process name.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\wsl.exe") and not (((action_process_image_name = "wsl.exe") or (action_process_image_name = null))))
