// Title: Potential Signing Bypass Via Windows Developer Features
// ID: a383dec4-deec-4e6e-913b-ed9249670848
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.stealth
// Description: Detects when a user enable developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "TurnOnDeveloperFeatures") and ((action_process_image_path endswith "\\SystemSettingsAdminFlows.exe") or (action_process_image_name = "SystemSettingsAdminFlows.EXE")) and ((action_process_image_command_line contains "DeveloperUnlock" or action_process_image_command_line contains "EnableSideloading")))
