# Title: Classes Autorun Keys Modification
# ID: 9df5f547-c86a-433e-b533-f2794357e242
# Status: test
# Level: medium
# Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
# Date: 2019-10-25
# Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
# Description: Detects modification of Windows Registry Classes keys used for persistence.
# Adversaries modify these autostart extensibility points (ASEP) to execute malicious code when file types are opened or actions are performed.
# Various legitimate software also uses these keys. Currently, this rule only filters out known legitimate software paths,
# thus it is recommended to review and tune filters for your environment to reduce false positives before deploying to production.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Classes Autorun Keys Modification
def rule(event):
    # Detection Logic:
    # (((TargetObject="*\\Software\\Classes*") AND ((TargetObject="*\\Folder\\ShellEx\\ExtShellFolderViews*" OR TargetObject="*\\Folder\\ShellEx\\DragDropHandlers*" OR TargetObject="*\\Folder\\Shellex\\ColumnHandlers*" OR TargetObject="*\\Filter*" OR TargetObject="*\\Exefile\\Shell\\Open\\Command\\(Default)*" OR TargetObject="*\\Directory\\Shellex\\DragDropHandlers*" OR TargetObject="*\\Directory\\Shellex\\CopyHookHandlers*" OR TargetObject="*\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance*" OR TargetObject="*\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance*" OR TargetObject="*\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance*" OR TargetObject="*\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance*" OR TargetObject="*\\Classes\\AllFileSystemObjects\\ShellEx\\DragDropHandlers*" OR TargetObject="*\\.exe*" OR TargetObject="*\\.cmd*" OR TargetObject="*\\ShellEx\\PropertySheetHandlers*" OR TargetObject="*\\ShellEx\\ContextMenuHandlers*"))) AND NOT (((Image="C:\\Windows\\System32\\drvinst.exe") OR (Details="(Empty)") OR (NOT Details=*) OR (Image="C:\\Windows\\System32\\svchost.exe" AND TargetObject="*\\lnkfile\\shellex\\ContextMenuHandlers\\*"))) AND NOT ((Details="{807583E5-5146-11D5-A672-00B0D022E945}")))
    return True

def title(event):
    return "Classes Autorun Keys Modification"

