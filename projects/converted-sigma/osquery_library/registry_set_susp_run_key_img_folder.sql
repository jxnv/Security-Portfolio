-- Title: New RUN Key Pointing to Suspicious Folder
-- ID: 02ee49e2-e294-4d0f-9278-f5b3212fc588
-- Status: experimental
-- Level: high
-- Author: Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2018-08-25
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%')) AND (((Details LIKE '%:\\Perflogs%' OR Details LIKE '%:\\ProgramData'%' OR Details LIKE '%:\\Windows\\Temp%' OR Details LIKE '%:\\Temp%' OR Details LIKE '%\\AppData\\Local\\Temp%' OR Details LIKE '%\\AppData\\Roaming%' OR Details LIKE '%:\\$Recycle.bin%' OR Details LIKE '%:\\Users\\Default%' OR Details LIKE '%:\\Users\\public%' OR Details LIKE '%%temp%%' OR Details LIKE '%%tmp%%' OR Details LIKE '%%Public%%' OR Details LIKE '%%AppData%%')) OR ((Details LIKE '%:\\Users\\%') AND ((Details LIKE '%\\Favorites%' OR Details LIKE '%\\Favourites%' OR Details LIKE '%\\Contacts%' OR Details LIKE '%\\Music%' OR Details LIKE '%\\Pictures%' OR Details LIKE '%\\Documents%' OR Details LIKE '%\\Photos%')))) AND NOT ((TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\%' AND Image="C:\\Windows\\SoftwareDistribution\\Download\\*" AND (Details LIKE '%rundll32.exe %' AND Details LIKE '%C:\\WINDOWS\\system32\\advpack.dll,DelNodeRunDLL32%') AND (Details LIKE '%\\AppData\\Local\\Temp\\%' OR Details LIKE '%C:\\Windows\\Temp\\%'))) AND NOT (((Image="*C:\\Program Files\\Spotify\\Spotify.exe" OR Image="*C:\\Program Files (x86)\\Spotify\\Spotify.exe" OR Image="*\\AppData\\Roaming\\Spotify\\Spotify.exe") AND TargetObject="*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Spotify" AND Details="*Spotify.exe --autostart --minimized")))
