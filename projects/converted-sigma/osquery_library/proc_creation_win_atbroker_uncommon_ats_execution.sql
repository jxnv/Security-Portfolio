-- Title: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
-- ID: f24bcaea-0cd1-11eb-adc1-0242ac120002
-- Status: test
-- Level: medium
-- Author: Mateusz Wydra, oscd.community
-- Date: 2020-10-12
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%start%') AND ((Image="*\\AtBroker.exe") OR (OriginalFileName = 'AtBroker.exe'))) AND NOT (((CommandLine LIKE '%animations%' OR CommandLine LIKE '%audiodescription%' OR CommandLine LIKE '%caretbrowsing%' OR CommandLine LIKE '%caretwidth%' OR CommandLine LIKE '%colorfiltering%' OR CommandLine LIKE '%cursorindicator%' OR CommandLine LIKE '%cursorscheme%' OR CommandLine LIKE '%filterkeys%' OR CommandLine LIKE '%focusborderheight%' OR CommandLine LIKE '%focusborderwidth%' OR CommandLine LIKE '%highcontrast%' OR CommandLine LIKE '%keyboardcues%' OR CommandLine LIKE '%keyboardpref%' OR CommandLine LIKE '%livecaptions%' OR CommandLine LIKE '%magnifierpane%' OR CommandLine LIKE '%messageduration%' OR CommandLine LIKE '%minimumhitradius%' OR CommandLine LIKE '%mousekeys%' OR CommandLine LIKE '%Narrator%' OR CommandLine LIKE '%osk%' OR CommandLine LIKE '%overlappedcontent%' OR CommandLine LIKE '%showsounds%' OR CommandLine LIKE '%soundsentry%' OR CommandLine LIKE '%speechreco%' OR CommandLine LIKE '%stickykeys%' OR CommandLine LIKE '%togglekeys%' OR CommandLine LIKE '%voiceaccess%' OR CommandLine LIKE '%windowarranging%' OR CommandLine LIKE '%windowtracking%' OR CommandLine LIKE '%windowtrackingtimeout%' OR CommandLine LIKE '%windowtrackingzorder%'))) AND NOT ((CommandLine LIKE '%Oracle_JavaAccessBridge%')))
