## Microsoft Azure Linux Agent Maintenance Guide

### Version rules

  * Production releases are public
  * Test releases are for internal use
  * Production versions use only [major].[minor].[revision]
  * Test versions use [major].[minor].[revision].[build]
  * Test a.b.c.0 is equivalent to Prod a.b.c
  * Publishing to Production requires incrementing the revision and dropping the build number
  * We do not use pre-release labels on any builds
  
### Version updates

  * The version of the agent can be found at https://github.com/Azure/WALinuxAgent/blob/master/azurelinuxagent/common/version.py#L53 assigned to AGENT_VERSION
  * Update the version here and send for PR before declaring a release via GitHub
