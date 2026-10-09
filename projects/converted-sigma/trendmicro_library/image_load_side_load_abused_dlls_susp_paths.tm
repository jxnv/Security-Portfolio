// Title: Abusable DLL Potential Sideloading From Suspicious Location
// ID: 799a5f48-0ac1-4e0f-9152-71d137d48c2a
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-07-11
// Tags: attack.execution, attack.t1059
// Description: Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

(((ImageLoaded="*\\coreclr.dll" OR ImageLoaded="*\\facesdk.dll" OR ImageLoaded="*\\HPCustPartUI.dll" OR ImageLoaded="*\\libcef.dll" OR ImageLoaded="*\\ZIPDLL.dll")) AND (((ImageLoaded: "*:\\Perflogs\\*" OR ImageLoaded: "*:\\Users\\Public\\*" OR ImageLoaded: "*\\Temporary Internet*" OR ImageLoaded: "*\\Windows\\Temp\\*")) OR (((ImageLoaded: "*:\\Users\\*" AND ImageLoaded: "*\\Favorites\\*")) OR ((ImageLoaded: "*:\\Users\\*" AND ImageLoaded: "*\\Favourites\\*")) OR ((ImageLoaded: "*:\\Users\\*" AND ImageLoaded: "*\\Contacts\\*")) OR ((ImageLoaded: "*:\\Users\\*" AND ImageLoaded: "*\\Pictures\\*")))))
