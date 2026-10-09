// Title: AWS User Login Profile Was Modified
// ID: 055fb148-60f8-462d-ad16-26926ce050f1
// Status: test
// Level: high
// Author: toffeebr33k
// Date: 2021-08-09
// Tags: attack.persistence, attack.privilege-escalation, attack.t1098
// Description: Detects activity when someone is changing passwords on behalf of other users.
// An attacker with the "iam:UpdateLoginProfile" permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.
// Converted by: Sigma Universal SIEM/EDR CLI

((eventSource: "iam.amazonaws.com" AND eventName: "UpdateLoginProfile") AND NOT ((userIdentity.arn=requestParameters.userName)))
