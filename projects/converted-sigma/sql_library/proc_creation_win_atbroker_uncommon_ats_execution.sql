-- Title: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
-- ID: f24bcaea-0cd1-11eb-adc1-0242ac120002
-- Status: test
-- Level: medium
-- Author: Mateusz Wydra, oscd.community
-- Date: 2020-10-12
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%start%') AND ((Image ILIKE '%\\AtBroker.exe') OR (OriginalFileName = 'AtBroker.exe'))) AND NOT (((CommandLine ILIKE '%animations%' OR CommandLine ILIKE '%audiodescription%' OR CommandLine ILIKE '%caretbrowsing%' OR CommandLine ILIKE '%caretwidth%' OR CommandLine ILIKE '%colorfiltering%' OR CommandLine ILIKE '%cursorindicator%' OR CommandLine ILIKE '%cursorscheme%' OR CommandLine ILIKE '%filterkeys%' OR CommandLine ILIKE '%focusborderheight%' OR CommandLine ILIKE '%focusborderwidth%' OR CommandLine ILIKE '%highcontrast%' OR CommandLine ILIKE '%keyboardcues%' OR CommandLine ILIKE '%keyboardpref%' OR CommandLine ILIKE '%livecaptions%' OR CommandLine ILIKE '%magnifierpane%' OR CommandLine ILIKE '%messageduration%' OR CommandLine ILIKE '%minimumhitradius%' OR CommandLine ILIKE '%mousekeys%' OR CommandLine ILIKE '%Narrator%' OR CommandLine ILIKE '%osk%' OR CommandLine ILIKE '%overlappedcontent%' OR CommandLine ILIKE '%showsounds%' OR CommandLine ILIKE '%soundsentry%' OR CommandLine ILIKE '%speechreco%' OR CommandLine ILIKE '%stickykeys%' OR CommandLine ILIKE '%togglekeys%' OR CommandLine ILIKE '%voiceaccess%' OR CommandLine ILIKE '%windowarranging%' OR CommandLine ILIKE '%windowtracking%' OR CommandLine ILIKE '%windowtrackingtimeout%' OR CommandLine ILIKE '%windowtrackingzorder%'))) AND NOT ((CommandLine ILIKE '%Oracle_JavaAccessBridge%')))
