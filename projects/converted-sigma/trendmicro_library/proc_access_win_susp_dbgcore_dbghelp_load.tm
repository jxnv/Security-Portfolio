// Title: Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs
// ID: 9f5c1d59-33be-4e60-bcab-85d2f566effd
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-27
// Tags: attack.credential-access, attack.defense-impairment, attack.t1003.001, attack.t1685
// Description: Detects suspicious process access to LSASS.exe from processes located in uncommon locations with dbgcore.dll or dbghelp.dll in the call trace.
// These DLLs contain functions like MiniDumpWriteDump that can be abused for credential dumping purposes. While modern tools like Mimikatz have moved to using ntdll.dll,
// dbgcore.dll and dbghelp.dll are still used by basic credential dumping utilities and legacy tools for LSASS memory access and process suspension techniques.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetImage="*\\lsass.exe" AND (CallTrace: "*dbgcore.dll*" OR CallTrace: "*dbghelp.dll*")) AND ((SourceImage: "*:\\Perflogs\\*" OR SourceImage: "*:\\Temp\\*" OR SourceImage: "*:\\Users\\Public\\*" OR SourceImage: "*\\$Recycle.Bin\\*" OR SourceImage: "*\\AppData\\Roaming\\*" OR SourceImage: "*\\Contacts\\*" OR SourceImage: "*\\Desktop\\*" OR SourceImage: "*\\Documents\\*" OR SourceImage: "*\\Downloads\\*" OR SourceImage: "*\\Favorites\\*" OR SourceImage: "*\\Favourites\\*" OR SourceImage: "*\\inetpub\\wwwroot\\*" OR SourceImage: "*\\Music\\*" OR SourceImage: "*\\Pictures\\*" OR SourceImage: "*\\Start Menu\\Programs\\Startup\\*" OR SourceImage: "*\\Users\\Default\\*" OR SourceImage: "*\\Videos\\*" OR SourceImage: "*\\Windows\\Temp\\*")))
