// Title: Wow6432Node Classes Autorun Keys Modification
// ID: 18f2065c-d36c-464a-a748-bcf909acb2e3
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects modification of autostart extensibility point (ASEP) in registry.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Software\\Wow6432Node\\Classes") and ((TargetObject contains "\\Folder\\ShellEx\\ExtShellFolderViews" or TargetObject contains "\\Folder\\ShellEx\\DragDropHandlers" or TargetObject contains "\\Folder\\ShellEx\\ColumnHandlers" or TargetObject contains "\\Directory\\Shellex\\DragDropHandlers" or TargetObject contains "\\Directory\\Shellex\\CopyHookHandlers" or TargetObject contains "\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance" or TargetObject contains "\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance" or TargetObject contains "\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance" or TargetObject contains "\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance" or TargetObject contains "\\AllFileSystemObjects\\ShellEx\\DragDropHandlers" or TargetObject contains "\\ShellEx\\PropertySheetHandlers" or TargetObject contains "\\ShellEx\\ContextMenuHandlers")) and not ((Details = "(Empty)")))
