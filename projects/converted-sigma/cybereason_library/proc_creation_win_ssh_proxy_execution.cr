// Title: Program Executed Using Proxy/Local Command Via SSH.EXE
// ID: 7d6d30b8-5b91-4b90-a891-46cccaf29598
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali
// Date: 2022-12-29
// Tags: attack.stealth, attack.t1218
// Description: Detect usage of the "ssh.exe" binary as a proxy to launch other programs.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage == "C:\\Windows\\System32\\OpenSSH\\sshd.exe") OR (((CommandLine contains "ProxyCommand=") OR ((CommandLine contains "PermitLocalCommand=yes" AND CommandLine contains " LocalCommand"))) AND ((Image="*\\ssh.exe") OR (Product == "OpenSSH for Windows") OR ((Hashes contains "IMPHASH=55b4964d29aad5438b9e950052dbbbc0" OR Hashes contains "IMPHASH=334d66c33503ccbf647c15b47c27eef4" OR Hashes contains "IMPHASH=27b0da080ef92afb37983d30d839141e" OR Hashes contains "IMPHASH=977eb4c263d384e47daa0712d34713ab" OR Hashes contains "IMPHASH=3eaadce9ae43d5a918bb082065815c3b" OR Hashes contains "IMPHASH=980fe6cf0d996ab1eedf877222e722aa" OR Hashes contains "IMPHASH=5f959422308ac3d721010d66647e100e" OR Hashes contains "IMPHASH=a49aaa3d03d1cd9c8dc7fca60f7f480b" OR Hashes contains "IMPHASH=dd335f759b6d5d6a8382b71dd9d65791")))))
