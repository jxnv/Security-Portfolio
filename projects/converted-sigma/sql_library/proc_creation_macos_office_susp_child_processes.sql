-- Title: Suspicious Microsoft Office Child Process - MacOS
-- ID: 69483748-1525-4a6c-95ca-90dc8d431b68
-- Status: test
-- Level: high
-- Author: Sohan G (D4rkCiph3r)
-- Date: 2023-01-31
-- Tags: attack.execution, attack.persistence, attack.t1059.002, attack.t1137.002, attack.t1204.002
-- Description: Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ParentImage ILIKE '%Microsoft Word%' OR ParentImage ILIKE '%Microsoft Excel%' OR ParentImage ILIKE '%Microsoft PowerPoint%' OR ParentImage ILIKE '%Microsoft OneNote%') AND (Image ILIKE '%/bash' OR Image ILIKE '%/curl' OR Image ILIKE '%/dash' OR Image ILIKE '%/fish' OR Image ILIKE '%/osacompile' OR Image ILIKE '%/osascript' OR Image ILIKE '%/sh' OR Image ILIKE '%/zsh' OR Image ILIKE '%/python' OR Image ILIKE '%/python3' OR Image ILIKE '%/wget'))
