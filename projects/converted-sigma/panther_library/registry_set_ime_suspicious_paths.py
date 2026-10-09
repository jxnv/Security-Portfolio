# Title: Suspicious Path In Keyboard Layout IME File Registry Value
# ID: 9d8f9bb8-01af-4e15-a3a2-349071530530
# Status: test
# Level: high
# Author: X__Junior (Nextron Systems)
# Date: 2023-11-21
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects usage of Windows Input Method Editor (IME) keyboard layout feature, which allows an attacker to load a DLL into the process after sending the WM_INPUTLANGCHANGEREQUEST message.
# Before doing this, the client needs to register the DLL in a special registry key that is assumed to implement this keyboard layout. This registry key should store a value named "Ime File" with a DLL path.
# IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Path In Keyboard Layout IME File Registry Value
def rule(event):
    # Detection Logic:
    # (((TargetObject="*\\Control\\Keyboard Layouts\\*" AND TargetObject="*Ime File*")) AND (((Details="*:\\Perflogs\\*" OR Details="*:\\Users\\Public\\*" OR Details="*:\\Windows\\Temp\\*" OR Details="*\\AppData\\Local\\Temp\\*" OR Details="*\\AppData\\Roaming\\*" OR Details="*\\Temporary Internet*")) OR (((Details="*:\\Users\\*" AND Details="*\\Favorites\\*")) OR ((Details="*:\\Users\\*" AND Details="*\\Favourites\\*")) OR ((Details="*:\\Users\\*" AND Details="*\\Contacts\\*")))))
    return True

def title(event):
    return "Suspicious Path In Keyboard Layout IME File Registry Value"

