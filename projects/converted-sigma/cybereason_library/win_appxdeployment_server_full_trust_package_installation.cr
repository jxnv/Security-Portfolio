// Title: Windows AppX Deployment Full Trust Package Installation
// ID: e54279c7-4910-4e2c-902c-c56a25b549f6
// Status: experimental
// Level: medium
// Author: Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-03
// Tags: attack.execution, attack.defense-impairment, attack.t1204.002, attack.t1553.005
// Description: Detects the installation of MSIX/AppX packages with full trust privileges which run with elevated privileges outside normal AppX container restrictions
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "400" AND HasFullTrust == "True") AND NOT ((((CallingProcess="sysprep.exe*" OR CallingProcess="svchost.exe,AppReadiness*")) OR ((PackageSourceUri="file:///C:/Program%20Files/*" OR PackageSourceUri="file:///C:/Program%20Files%20(x86)/*")) OR ((PackageSourceUri="https://go.microsoft.com/fwlink/?linkid*") OR ((PackageSourceUri contains ".cdn.microsoft.com" OR PackageSourceUri contains ".cdn.office.net/"))))) AND NOT (((PackageFullName="MicrosoftWindows.Client.*") OR (PackageSourceUri="x-windowsupdate://*"))))
