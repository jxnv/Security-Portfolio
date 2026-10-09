// Title: Office Macro File Download
// ID: 0e29e3a7-1ad8-40aa-b691-9f82ecd33d66
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-23
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of a new office macro files on the system via an application (browser, mail client).
// This can help identify potential malicious activity, such as the download of macro-enabled documents that could be used for exploitation.
// Converted by: Sigma Universal SIEM/EDR CLI

((((TargetFilename="*.docm" OR TargetFilename="*.dotm" OR TargetFilename="*.xlsm" OR TargetFilename="*.xltm" OR TargetFilename="*.potm" OR TargetFilename="*.pptm")) OR ((TargetFilename contains ".docm:Zone" OR TargetFilename contains ".dotm:Zone" OR TargetFilename contains ".xlsm:Zone" OR TargetFilename contains ".xltm:Zone" OR TargetFilename contains ".potm:Zone" OR TargetFilename contains ".pptm:Zone"))) AND ((Image="*\\RuntimeBroker.exe" OR Image="*\\outlook.exe" OR Image="*\\thunderbird.exe" OR Image="*\\brave.exe" OR Image="*\\chrome.exe" OR Image="*\\firefox.exe" OR Image="*\\iexplore.exe" OR Image="*\\maxthon.exe" OR Image="*\\MicrosoftEdge.exe" OR Image="*\\msedge.exe" OR Image="*\\msedgewebview2.exe" OR Image="*\\opera.exe" OR Image="*\\safari.exe" OR Image="*\\seamonkey.exe" OR Image="*\\vivaldi.exe" OR Image="*\\whale.exe")))
