-- Title: HackTool - Empire PowerShell Launch Parameters
-- ID: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-04-20
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious powershell command line parameters used in Empire
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% -NoP -sta -NonI -W Hidden -Enc %' OR CommandLine LIKE '% -noP -sta -w 1 -enc %' OR CommandLine LIKE '% -NoP -NonI -W Hidden -enc %' OR CommandLine LIKE '% -noP -sta -w 1 -enc%' OR CommandLine LIKE '% -enc  SQB%' OR CommandLine LIKE '% -nop -exec bypass -EncodedCommand %'))
