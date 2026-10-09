# Title: Office Autorun Keys Modification
# ID: baecf8fb-edbf-429f-9ade-31fc3f22b970
# Status: test
# Level: medium
# Author: Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
# Date: 2019-10-25
# Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
# Description: Detects modification of autostart extensibility point (ASEP) in registry. Adversaries may modify these keys to execute malicious code when Office files are opened.
# There are various legitimate add-ins that also use these keys and this filter list might not be exhaustive.
# Thus, it is recommended to review and tune filters for your environment to reduce false positives before deploying to production.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Office Autorun Keys Modification
def rule(event):
    # Detection Logic:
    # ((((TargetObject="*\\Word\\Addins*" OR TargetObject="*\\PowerPoint\\Addins*" OR TargetObject="*\\Outlook\\Addins*" OR TargetObject="*\\Onenote\\Addins*" OR TargetObject="*\\Excel\\Addins*" OR TargetObject="*\\Access\\Addins*" OR TargetObject="*test\\Special\\Perf*")) AND ((TargetObject="*\\Software\\Wow6432Node\\Microsoft\\Office*" OR TargetObject="*\\Software\\Microsoft\\Office*"))) AND NOT (((Details="(Empty)") OR ((Image="C:\\Program Files\\Microsoft Office\\*" OR Image="C:\\Program Files (x86)\\Microsoft Office\\*" OR Image="C:\\PROGRA~2\\MICROS~2\\Office*" OR Image="C:\\Windows\\System32\\msiexec.exe*" OR Image="C:\\Windows\\SysWOW64\\msiexec.exe*" OR Image="C:\\Windows\\System32\\regsvr32.exe*" OR Image="C:\\Windows\\SysWOW64\\regsvr32.exe*") AND (TargetObject="*\\Excel\\Addins\\AdHocReportingExcelClientLib.AdHocReportingExcelClientAddIn.1\\*" OR TargetObject="*\\Excel\\Addins\\ExcelPlugInShell.PowerMapConnect\\*" OR TargetObject="*\\Excel\\Addins\\NativeShim\\*" OR TargetObject="*\\Excel\\Addins\\NativeShim.InquireConnector.1\\*" OR TargetObject="*\\Excel\\Addins\\PowerPivotExcelClientAddIn.NativeEntry.1\\*" OR TargetObject="*\\Outlook\\AddIns\\AccessAddin.DC\\*" OR TargetObject="*\\Outlook\\AddIns\\ColleagueImport.ColleagueImportAddin\\*" OR TargetObject="*\\Outlook\\AddIns\\EvernoteCC.EvernoteContactConnector\\*" OR TargetObject="*\\Outlook\\AddIns\\EvernoteOLRD.Connect\\*" OR TargetObject="*\\Outlook\\Addins\\OneNote.OutlookAddin*" OR TargetObject="*\\Outlook\\Addins\\DriveFSExtensionLib.Connect\\*" OR TargetObject="*\\Outlook\\Addins\\GoogleAppsSync.Connect\\*" OR TargetObject="*\\Outlook\\Addins\\Microsoft.VbaAddinForOutlook.1\\*" OR TargetObject="*\\Outlook\\Addins\\OcOffice.OcForms\\*" OR TargetObject="*\\Outlook\\Addins\\OscAddin.Connect\\*" OR TargetObject="*\\Outlook\\Addins\\OutlookChangeNotifier.Connect\\*" OR TargetObject="*\\Outlook\\Addins\\UCAddin.LyncAddin.1*" OR TargetObject="*\\Outlook\\Addins\\UCAddin.UCAddin.1*" OR TargetObject="*\\Outlook\\Addins\\UmOutlookAddin.FormRegionAddin\\*" OR TargetObject="*AddinTakeNotesService\\FriendlyName*")) OR (NOT Details=*) OR ((Image="C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\*" OR Image="C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\*") AND Image="*\\OfficeClickToRun.exe") OR ((Image="C:\\Program Files\\Common Files\\Microsoft Shared\\VSTO\\*" OR Image="C:\\Program Files (x86)\\Microsoft Shared\\VSTO\\*") AND Image="*\\VSTOInstaller.exe"))) AND NOT ((((Image="C:\\Program Files\\Avast Software\\Avast\\RegSvr.exe" OR Image="C:\\Program Files\\Avast Software\\Avast\\x86\\RegSvr.exe") AND TargetObject="*\\Microsoft\\Office\\Outlook\\Addins\\Avast.AsOutExt\\*") OR ((Image="C:\\Program Files\\AVG\\Antivirus\\RegSvr.exe" OR Image="C:\\Program Files\\AVG\\Antivirus\\x86\\RegSvr.exe") AND TargetObject="*\\Microsoft\\Office\\Outlook\\Addins\\Antivirus.AsOutExt\\*"))))
    return True

def title(event):
    return "Office Autorun Keys Modification"

