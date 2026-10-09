// Title: Potential Persistence Via Notepad++ Plugins
// ID: 54127bd4-f541-4ac3-afdb-ea073f63f692
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-10
// Tags: attack.persistence
// Description: Detects creation of new ".dll" files inside the plugins directory of a notepad++ installation by a process other than "gup.exe". Which could indicates possible persistence
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\Notepad++\\plugins\\" and action_file_path endswith ".dll") and not (((action_process_image_path endswith "\\Notepad++\\updater\\gup.exe") or (action_process_image_path startswith "C:\\Users\\" and action_process_image_path contains "\\AppData\\Local\\Temp\\" and (action_process_image_path endswith "\\target.exe" or action_process_image_path endswith "Installer.x64.exe")) or (action_process_image_path contains "\\npp." and action_process_image_path endswith ".exe" and (action_file_path = "C:\\Program Files\\Notepad++\\plugins\\NppExport\\NppExport.dll" or action_file_path = "C:\\Program Files\\Notepad++\\plugins\\mimeTools\\mimeTools.dll" or action_file_path = "C:\\Program Files\\Notepad++\\plugins\\NppConverter\\NppConverter.dll" or action_file_path = "C:\\Program Files\\Notepad++\\plugins\\Config\\nppPluginList.dll")))))
