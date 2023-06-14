# Agent Extension Worflow Test

This scenario tests if the correct extension workflow sequence is being executed from the agent.

### GuestAgentDcrTestExtension

This is a test extension that exists for the sole purpose of testing the extension workflow of agent. This is currently deployed to SCUS only.

All the extension does is prints the settings['name'] out to stdout. It is run everytime enable is called.

Another important feature of this extension is that it maintains a `operations-<VERSION_NO>.log` **for every operation that the agent executes on that extension**. We use this to confirm that the agent executed the correct sequence of operations.

Sample operations-<version>.log file snippet -
```text
Date:2019-07-30T21:54:03Z; Operation:install; SeqNo:0
Date:2019-07-30T21:54:05Z; Operation:enable; SeqNo:0
Date:2019-07-30T21:54:37Z; Operation:enable; SeqNo:1
Date:2019-07-30T21:55:20Z; Operation:disable; SeqNo:1
Date:2019-07-30T21:55:22Z; Operation:uninstall; SeqNo:1
```
The setting for this extension is of the format - 
```json
{
  "name": String
}
```
##### Repo link 
https://github.com/larohra/GuestAgentDcrTestExtension 

##### Availabe Versions:
- 1.1.5 - Version with Basic functionalities as mentioned above
- 1.2.0 - Same functionalities as above with `"updateMode": "UpdateWithInstall"` in HandlerManifest.json to test update case
- 1.3.0 - Same functionalities as above with `"updateMode": "UpdateWithoutInstall"` in HandlerManifest.json to test update case

### Test Sequence 

- Install the test extension on the VM
- Assert the extension status by checking if our Enable string matches the status message (We receive the status message by using the Azure SDK by polling for the VM instance view and parsing the extension status message)  

The Enable string of our test is of the following format (this is set in the `Settings` object when we call enable from the tests ) -
```text
[ExtensionName]-[Version], Count: [Enable-count]
```
- Match the operation sequence as per the test and make sure they are in the correct chronological order
- Restart the agent and verify if the correct operation sequence is followed