// Title: Potential Persistence Via Microsoft Office Startup Folder
// ID: 0e20c89d-2264-44ae-8238-aeeaba609ece
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-02
// Tags: attack.persistence, attack.t1137
// Description: Detects creation of Microsoft Office files inside of one of the default startup folders in order to achieve persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

(((((TargetFilename="*.doc" OR TargetFilename="*.docm" OR TargetFilename="*.docx" OR TargetFilename="*.dot" OR TargetFilename="*.dotm" OR TargetFilename="*.rtf")) AND ((TargetFilename contains "\\Microsoft\\Word\\STARTUP") OR ((TargetFilename contains "\\Office" AND TargetFilename contains "\\Program Files" AND TargetFilename contains "\\STARTUP")))) OR (((TargetFilename="*.xls" OR TargetFilename="*.xlsm" OR TargetFilename="*.xlsx" OR TargetFilename="*.xlt" OR TargetFilename="*.xltm")) AND ((TargetFilename contains "\\Microsoft\\Excel\\XLSTART") OR ((TargetFilename contains "\\Office" AND TargetFilename contains "\\Program Files" AND TargetFilename contains "\\XLSTART"))))) AND NOT (((Image="*\\WINWORD.exe" OR Image="*\\EXCEL.exe"))))
