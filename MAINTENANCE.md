## Microsoft Azure Linux Agent Maintenance Guide

### Version rules

  * Production releases are public
  * Test releases are for internal use
  * Production versions use only [major].[minor].[revision]
  * Test versions use [major].[minor].[revision].[build]
  * Test a.b.c.0 is equivalent to Prod a.b.c
  * Publishing to Production requires incrementing the revision and dropping the build number
  * We do not use pre-release labels on any builds
  