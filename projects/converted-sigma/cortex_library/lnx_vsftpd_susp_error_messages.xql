// Title: Suspicious VSFTPD Error Messages
// ID: 377f33a1-4b36-4ee1-acee-1dbe4b43cfbe
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-07-05
// Tags: attack.initial-access, attack.t1190
// Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ("Connection refused: too many sessions for this address." or "Connection refused: tcp_wrappers denial." or "Bad HTTP verb." or "port and pasv both active" or "pasv and port both active" or "Transfer done (but failed to open directory)." or "Could not set file modification time." or "bug: pid active in ptrace_sandbox_free" or "PTRACE_SETOPTIONS failure" or "weird status:" or "couldn't handle sandbox event" or "syscall * out of bounds" or "syscall not permitted:" or "syscall validate failed:" or "Input line too long." or "poor buffer accounting in str_netfd_alloc" or "vsf_sysutil_read_loop")
