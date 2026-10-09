// Title: New RUN Key Pointing to Suspicious Folder
// ID: 02ee49e2-e294-4d0f-9278-f5b3212fc588
// Status: experimental
// Level: high
// Author: Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2018-08-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" OR TargetObject contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" OR TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run")) AND (((Details contains ":\\Perflogs" OR Details contains ":\\ProgramData'" OR Details contains ":\\Windows\\Temp" OR Details contains ":\\Temp" OR Details contains "\\AppData\\Local\\Temp" OR Details contains "\\AppData\\Roaming" OR Details contains ":\\$Recycle.bin" OR Details contains ":\\Users\\Default" OR Details contains ":\\Users\\public" OR Details contains "%temp%" OR Details contains "%tmp%" OR Details contains "%Public%" OR Details contains "%AppData%")) OR ((Details contains ":\\Users\\") AND ((Details contains "\\Favorites" OR Details contains "\\Favourites" OR Details contains "\\Contacts" OR Details contains "\\Music" OR Details contains "\\Pictures" OR Details contains "\\Documents" OR Details contains "\\Photos")))) AND NOT ((TargetObject contains "\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\" AND Image="C:\\Windows\\SoftwareDistribution\\Download\\*" AND (Details contains "rundll32.exe " AND Details contains "C:\\WINDOWS\\system32\\advpack.dll,DelNodeRunDLL32") AND (Details contains "\\AppData\\Local\\Temp\\" OR Details contains "C:\\Windows\\Temp\\"))) AND NOT (((Image="*C:\\Program Files\\Spotify\\Spotify.exe" OR Image="*C:\\Program Files (x86)\\Spotify\\Spotify.exe" OR Image="*\\AppData\\Roaming\\Spotify\\Spotify.exe") AND TargetObject="*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Spotify" AND Details="*Spotify.exe --autostart --minimized")))
