// Title: Okta Application Modified or Deleted
// ID: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-09-12
// Tags: attack.impact
// Description: Detects when an application is modified or deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

((eventType == "application.lifecycle.update" OR eventType == "application.lifecycle.delete"))
