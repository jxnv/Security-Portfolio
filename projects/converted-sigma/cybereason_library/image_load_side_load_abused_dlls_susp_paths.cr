// Title: Abusable DLL Potential Sideloading From Suspicious Location
// ID: 799a5f48-0ac1-4e0f-9152-71d137d48c2a
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-07-11
// Tags: attack.execution, attack.t1059
// Description: Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

(((ImageLoaded="*\\coreclr.dll" OR ImageLoaded="*\\facesdk.dll" OR ImageLoaded="*\\HPCustPartUI.dll" OR ImageLoaded="*\\libcef.dll" OR ImageLoaded="*\\ZIPDLL.dll")) AND (((ImageLoaded contains ":\\Perflogs\\" OR ImageLoaded contains ":\\Users\\Public\\" OR ImageLoaded contains "\\Temporary Internet" OR ImageLoaded contains "\\Windows\\Temp\\")) OR (((ImageLoaded contains ":\\Users\\" AND ImageLoaded contains "\\Favorites\\")) OR ((ImageLoaded contains ":\\Users\\" AND ImageLoaded contains "\\Favourites\\")) OR ((ImageLoaded contains ":\\Users\\" AND ImageLoaded contains "\\Contacts\\")) OR ((ImageLoaded contains ":\\Users\\" AND ImageLoaded contains "\\Pictures\\")))))
