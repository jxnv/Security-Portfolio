// Title: Use of Legacy Authentication Protocols
// ID: 60f6535a-760f-42a9-be3f-c9a0a025906e
// Status: test
// Level: high
// Author: Yochana Henderson, '@Yochana-H'
// Date: 2022-06-17
// Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.credential-access, attack.stealth, attack.t1078.004, attack.t1110
// Description: Alert on when legacy authentication has been used on an account
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (ActivityDetails = "Sign-ins" and (ClientApp = "Other client" or ClientApp = "IMAP" or ClientApp = "POP3" or ClientApp = "MAPI" or ClientApp = "SMTP" or ClientApp = "Exchange ActiveSync" or ClientApp = "Exchange Web Services") and Username = "UPN")
