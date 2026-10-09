// Title: Malicious Named Pipe Created
// ID: fe3ac066-98bb-432a-b1e7-a5229cb39d4a
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), blueteam0ps, elhoim
// Date: 2017-11-06
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects the creation of a named pipe seen used by known APTs or malware.
// Converted by: Sigma Universal SIEM/EDR CLI

((PipeName == "\\46a676ab7f179e511e30dd2dc41bd388" OR PipeName == "\\583da945-62af-10e8-4902-a8f205c72b2e" OR PipeName == "\\6e7645c4-32c5-4fe3-aabf-e94c2f4370e7" OR PipeName == "\\9f81f59bc58452127884ce513865ed20" OR PipeName == "\\adschemerpc" OR PipeName == "\\ahexec" OR PipeName == "\\AnonymousPipe" OR PipeName == "\\bc31a7" OR PipeName == "\\bc367" OR PipeName == "\\bizkaz" OR PipeName == "\\csexecsvc" OR PipeName == "\\dce_3d" OR PipeName == "\\e710f28d59aa529d6792ca6ff0ca1b34" OR PipeName == "\\gruntsvc" OR PipeName == "\\isapi_dg" OR PipeName == "\\isapi_dg2" OR PipeName == "\\isapi_http" OR PipeName == "\\jaccdpqnvbrrxlaf" OR PipeName == "\\lsassw" OR PipeName == "\\NamePipe_MoreWindows" OR PipeName == "\\pcheap_reuse" OR PipeName == "\\Posh*" OR PipeName == "\\rpchlp_3" OR PipeName == "\\sdlrpc" OR PipeName == "\\svcctl" OR PipeName == "\\testPipe" OR PipeName == "\\winsession"))
