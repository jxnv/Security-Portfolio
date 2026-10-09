-- Title: HackTool - PPID Spoofing SelectMyParent Tool Execution
-- ID: 52ff7941-8211-46f9-84f8-9903efb7077d
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-07-23
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.004
-- Description: Detects the use of parent process ID spoofing tools like Didier Stevens tool SelectMyParent
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\SelectMyParent.exe') OR ((CommandLine ILIKE '%PPID-spoof%' OR CommandLine ILIKE '%ppid_spoof%' OR CommandLine ILIKE '%spoof-ppid%' OR CommandLine ILIKE '%spoof_ppid%' OR CommandLine ILIKE '%ppidspoof%' OR CommandLine ILIKE '%spoofppid%' OR CommandLine ILIKE '%spoofedppid%' OR CommandLine ILIKE '% -spawnto %')) OR ((OriginalFileName ILIKE '%PPID-spoof%' OR OriginalFileName ILIKE '%ppid_spoof%' OR OriginalFileName ILIKE '%spoof-ppid%' OR OriginalFileName ILIKE '%spoof_ppid%' OR OriginalFileName ILIKE '%ppidspoof%' OR OriginalFileName ILIKE '%spoofppid%' OR OriginalFileName ILIKE '%spoofedppid%')) OR (Description = 'SelectMyParent') OR ((Hashes ILIKE '%IMPHASH=04D974875BD225F00902B4CAD9AF3FBC%' OR Hashes ILIKE '%IMPHASH=A782AF154C9E743DDF3F3EB2B8F3D16E%' OR Hashes ILIKE '%IMPHASH=89059503D7FBF470E68F7E63313DA3AD%' OR Hashes ILIKE '%IMPHASH=CA28337632625C8281AB8A130B3D6BAD%')))
