// Title: Suspicious Process Parents
// ID: cbec226f-63d9-4eca-9f52-dfb6652f24df
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-21
// Tags: attack.stealth, attack.t1036
// Description: Detects suspicious parent processes that should not have any children or should only have a single possible child program
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((actor_process_image_path endswith "\\minesweeper.exe" or actor_process_image_path endswith "\\winver.exe" or actor_process_image_path endswith "\\bitsadmin.exe")) or (((actor_process_image_path endswith "\\csrss.exe" or actor_process_image_path endswith "\\certutil.exe" or actor_process_image_path endswith "\\eventvwr.exe" or actor_process_image_path endswith "\\calc.exe" or actor_process_image_path endswith "\\notepad.exe")) and not (((action_process_image_path = null) or ((action_process_image_path endswith "\\WerFault.exe" or action_process_image_path endswith "\\wermgr.exe" or action_process_image_path endswith "\\conhost.exe" or action_process_image_path endswith "\\mmc.exe" or action_process_image_path endswith "\\win32calc.exe" or action_process_image_path endswith "\\notepad.exe"))))))
