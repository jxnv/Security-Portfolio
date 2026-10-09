// Title: Renamed AutoHotkey.EXE Execution
// ID: 0f16d9cf-0616-45c8-8fad-becc11b5a41c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali
// Date: 2023-02-07
// Tags: attack.stealth
// Description: Detects execution of a renamed autohotkey.exe binary based on PE metadata fields
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Product contains "AutoHotkey") or (Description contains "AutoHotkey") or ((action_process_image_name = "AutoHotkey.exe" or action_process_image_name = "AutoHotkey.rc"))) and not ((((action_process_image_path endswith "\\AutoHotkey.exe" or action_process_image_path endswith "\\AutoHotkey32.exe" or action_process_image_path endswith "\\AutoHotkey32_UIA.exe" or action_process_image_path endswith "\\AutoHotkey64.exe" or action_process_image_path endswith "\\AutoHotkey64_UIA.exe" or action_process_image_path endswith "\\AutoHotkeyA32.exe" or action_process_image_path endswith "\\AutoHotkeyA32_UIA.exe" or action_process_image_path endswith "\\AutoHotkeyU32.exe" or action_process_image_path endswith "\\AutoHotkeyU32_UIA.exe" or action_process_image_path endswith "\\AutoHotkeyU64.exe" or action_process_image_path endswith "\\AutoHotkeyU64_UIA.exe")) or (action_process_image_path contains "\\AutoHotkey"))))
