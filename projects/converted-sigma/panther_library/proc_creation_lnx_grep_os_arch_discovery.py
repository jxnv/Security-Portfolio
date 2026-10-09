# Title: OS Architecture Discovery Via Grep
# ID: d27ab432-2199-483f-a297-03633c05bae6
# Status: test
# Level: low
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk
# Date: 2023-06-02
# Tags: attack.discovery, attack.t1082
# Description: Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OS Architecture Discovery Via Grep
def rule(event):
    # Detection Logic:
    # (((CommandLine="*aarch64" OR CommandLine="*arm" OR CommandLine="*i386" OR CommandLine="*i686" OR CommandLine="*mips" OR CommandLine="*x86_64")) AND (Image="*/grep"))
    return True

def title(event):
    return "OS Architecture Discovery Via Grep"

