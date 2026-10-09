-- Title: Desktop.INI Created by Uncommon Process
-- ID: 81315b50-6b60-4d8f-9928-3466e1022515
-- Status: test
-- Level: medium
-- Author: Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)
-- Date: 2020-03-19
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.009
-- Description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename="*\\desktop.ini") AND NOT ((((Image="C:\\Windows\\*" OR Image="C:\\Program Files\\*" OR Image="C:\\Program Files (x86)\\*")) OR (TargetFilename="C:\\$WINDOWS.~BT\\NewOS\\*"))) AND NOT (((Image="C:\\Users\\*" AND Image="*\\AppData\\Local\\JetBrains\\Toolbox\\bin\\7z.exe" AND TargetFilename LIKE '%\\JetBrains\\apps\\%') OR (Image="C:\\Users\\*" AND Image LIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\%'))))
