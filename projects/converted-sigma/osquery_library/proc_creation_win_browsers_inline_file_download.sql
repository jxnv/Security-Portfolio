-- Title: File Download From Browser Process Via Inline URL
-- ID: 94771a71-ba41-4b6e-a757-b531372eaab6
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-11
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine="*.7z" OR CommandLine="*.dat" OR CommandLine="*.dll" OR CommandLine="*.exe" OR CommandLine="*.hta" OR CommandLine="*.ps1" OR CommandLine="*.psm1" OR CommandLine="*.txt" OR CommandLine="*.vbe" OR CommandLine="*.vbs" OR CommandLine="*.zip")) OR ((CommandLine LIKE '%.7z\"%' OR CommandLine LIKE '%.dat\"%' OR CommandLine LIKE '%.dll\"%' OR CommandLine LIKE '%.hta\"%' OR CommandLine LIKE '%.ps1\"%' OR CommandLine LIKE '%.psm1\"%' OR CommandLine LIKE '%.txt\"%' OR CommandLine LIKE '%.vbe\"%' OR CommandLine LIKE '%.vbs\"%' OR CommandLine LIKE '%.zip\"%'))) AND (CommandLine LIKE '%http%') AND ((Image="*\\brave.exe" OR Image="*\\chrome.exe" OR Image="*\\msedge.exe" OR Image="*\\opera.exe" OR Image="*\\vivaldi.exe")))
