// Title: Suspicious Browser Child Process - MacOS
// ID: 0250638a-2b28-4541-86fc-ea4c558fa0c6
// Status: test
// Level: medium
// Author: Sohan G (D4rkCiph3r)
// Date: 2023-04-05
// Tags: attack.initial-access, attack.execution, attack.t1189, attack.t1203, attack.t1059
// Description: Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation.
// Converted by: Sigma Universal SIEM/EDR CLI

(((ParentImage: "*com.apple.WebKit.WebContent*" OR ParentImage: "*firefox*" OR ParentImage: "*Google Chrome Helper*" OR ParentImage: "*Google Chrome*" OR ParentImage: "*Microsoft Edge*" OR ParentImage: "*Opera*" OR ParentImage: "*Safari*" OR ParentImage: "*Tor Browser*") AND (Image="*/bash" OR Image="*/curl" OR Image="*/dash" OR Image="*/ksh" OR Image="*/osascript" OR Image="*/perl" OR Image="*/php" OR Image="*/pwsh" OR Image="*/python" OR Image="*/sh" OR Image="*/tcsh" OR Image="*/wget" OR Image="*/zsh")) AND NOT ((((ParentImage: "*Google Chrome Helper*" OR ParentImage: "*Google Chrome*") AND (CommandLine: "*/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh*" OR CommandLine: "*/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_preflight.sh*" OR CommandLine: "*/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_postflight.sh*")) OR ((ParentImage: "*Google Chrome Helper*" OR ParentImage: "*Google Chrome*") AND (CommandLine: "*/Users/*" AND CommandLine: "*/Library/Application Support/Google/Chrome/recovery/*" AND CommandLine: "*/ChromeRecovery*")) OR (CommandLine: "*--defaults-torrc*") OR (CommandLine: "*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*") OR (ParentImage: "*Microsoft Edge*" AND (CommandLine: "*IOPlatformExpertDevice*" OR CommandLine: "*hw.model*")))) AND NOT (((CommandLine: "") OR (NOT CommandLine=*))))
