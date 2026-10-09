-- Title: Suspicious Browser Child Process - MacOS
-- ID: 0250638a-2b28-4541-86fc-ea4c558fa0c6
-- Status: test
-- Level: medium
-- Author: Sohan G (D4rkCiph3r)
-- Date: 2023-04-05
-- Tags: attack.initial-access, attack.execution, attack.t1189, attack.t1203, attack.t1059
-- Description: Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage LIKE '%com.apple.WebKit.WebContent%' OR ParentImage LIKE '%firefox%' OR ParentImage LIKE '%Google Chrome Helper%' OR ParentImage LIKE '%Google Chrome%' OR ParentImage LIKE '%Microsoft Edge%' OR ParentImage LIKE '%Opera%' OR ParentImage LIKE '%Safari%' OR ParentImage LIKE '%Tor Browser%') AND (Image="*/bash" OR Image="*/curl" OR Image="*/dash" OR Image="*/ksh" OR Image="*/osascript" OR Image="*/perl" OR Image="*/php" OR Image="*/pwsh" OR Image="*/python" OR Image="*/sh" OR Image="*/tcsh" OR Image="*/wget" OR Image="*/zsh")) AND NOT ((((ParentImage LIKE '%Google Chrome Helper%' OR ParentImage LIKE '%Google Chrome%') AND (CommandLine LIKE '%/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh%' OR CommandLine LIKE '%/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_preflight.sh%' OR CommandLine LIKE '%/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_postflight.sh%')) OR ((ParentImage LIKE '%Google Chrome Helper%' OR ParentImage LIKE '%Google Chrome%') AND (CommandLine LIKE '%/Users/%' AND CommandLine LIKE '%/Library/Application Support/Google/Chrome/recovery/%' AND CommandLine LIKE '%/ChromeRecovery%')) OR (CommandLine LIKE '%--defaults-torrc%') OR (CommandLine LIKE '%/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate%') OR (ParentImage LIKE '%Microsoft Edge%' AND (CommandLine LIKE '%IOPlatformExpertDevice%' OR CommandLine LIKE '%hw.model%')))) AND NOT (((CommandLine = '') OR (NOT CommandLine=*))))
