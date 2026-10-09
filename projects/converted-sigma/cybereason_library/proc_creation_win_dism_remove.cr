// Title: Dism Remove Online Package
// ID: 43e32da2-fdd0-4156-90de-50dfd62636f9
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-16
// Tags: attack.defense-impairment, attack.t1685
// Description: Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\Dism.exe" AND (CommandLine contains "/Online" AND CommandLine contains "/Disable-Feature")) OR (Image="*\\DismHost.exe" AND (ParentCommandLine contains "/Online" AND ParentCommandLine contains "/Disable-Feature")))
