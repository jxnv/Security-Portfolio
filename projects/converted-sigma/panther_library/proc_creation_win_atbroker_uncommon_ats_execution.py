# Title: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
# ID: f24bcaea-0cd1-11eb-adc1-0242ac120002
# Status: test
# Level: medium
# Author: Mateusz Wydra, oscd.community
# Date: 2020-10-12
# Tags: attack.stealth, attack.t1218
# Description: Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*start*") AND ((Image="*\\AtBroker.exe") OR (OriginalFileName="AtBroker.exe"))) AND NOT (((CommandLine="*animations*" OR CommandLine="*audiodescription*" OR CommandLine="*caretbrowsing*" OR CommandLine="*caretwidth*" OR CommandLine="*colorfiltering*" OR CommandLine="*cursorindicator*" OR CommandLine="*cursorscheme*" OR CommandLine="*filterkeys*" OR CommandLine="*focusborderheight*" OR CommandLine="*focusborderwidth*" OR CommandLine="*highcontrast*" OR CommandLine="*keyboardcues*" OR CommandLine="*keyboardpref*" OR CommandLine="*livecaptions*" OR CommandLine="*magnifierpane*" OR CommandLine="*messageduration*" OR CommandLine="*minimumhitradius*" OR CommandLine="*mousekeys*" OR CommandLine="*Narrator*" OR CommandLine="*osk*" OR CommandLine="*overlappedcontent*" OR CommandLine="*showsounds*" OR CommandLine="*soundsentry*" OR CommandLine="*speechreco*" OR CommandLine="*stickykeys*" OR CommandLine="*togglekeys*" OR CommandLine="*voiceaccess*" OR CommandLine="*windowarranging*" OR CommandLine="*windowtracking*" OR CommandLine="*windowtrackingtimeout*" OR CommandLine="*windowtrackingzorder*"))) AND NOT ((CommandLine="*Oracle_JavaAccessBridge*")))
    return True

def title(event):
    return "Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE"

