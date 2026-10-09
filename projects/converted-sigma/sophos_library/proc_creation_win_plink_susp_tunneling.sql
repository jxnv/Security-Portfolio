-- Title: Potential RDP Tunneling Via Plink
-- ID: f38ce0b9-5e97-4b47-a211-7dc8d8b871da
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-04
-- Tags: attack.command-and-control, attack.t1572
-- Description: Execution of plink to perform data exfiltration and tunneling
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\plink.exe' AND CommandLine ILIKE '%:127.0.0.1:3389%') OR ((Image ILIKE '%\\plink.exe' AND CommandLine ILIKE '%:3389%') AND ((CommandLine ILIKE '% -P 443%' OR CommandLine ILIKE '% -P 22%'))))
