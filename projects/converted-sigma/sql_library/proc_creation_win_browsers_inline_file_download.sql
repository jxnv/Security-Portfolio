-- Title: File Download From Browser Process Via Inline URL
-- ID: 94771a71-ba41-4b6e-a757-b531372eaab6
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-11
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%.7z' OR CommandLine ILIKE '%.dat' OR CommandLine ILIKE '%.dll' OR CommandLine ILIKE '%.exe' OR CommandLine ILIKE '%.hta' OR CommandLine ILIKE '%.ps1' OR CommandLine ILIKE '%.psm1' OR CommandLine ILIKE '%.txt' OR CommandLine ILIKE '%.vbe' OR CommandLine ILIKE '%.vbs' OR CommandLine ILIKE '%.zip')) OR ((CommandLine ILIKE '%.7z\"%' OR CommandLine ILIKE '%.dat\"%' OR CommandLine ILIKE '%.dll\"%' OR CommandLine ILIKE '%.hta\"%' OR CommandLine ILIKE '%.ps1\"%' OR CommandLine ILIKE '%.psm1\"%' OR CommandLine ILIKE '%.txt\"%' OR CommandLine ILIKE '%.vbe\"%' OR CommandLine ILIKE '%.vbs\"%' OR CommandLine ILIKE '%.zip\"%'))) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\brave.exe' OR Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\opera.exe' OR Image ILIKE '%\\vivaldi.exe')))
