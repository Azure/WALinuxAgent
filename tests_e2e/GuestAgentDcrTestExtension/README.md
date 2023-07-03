# GuestAgentDcrTestExtension

#### Before publishing a new version
- Make sure all changes are pushed in master
- Change the Version in Manifest.xml and push it in master 
- Create a tag with the same version number

### To publish a new Test version
- Go to [EDP pipeline page](https://tuxgold.corp.microsoft.com/job/EDP/job/Microsoft.Azure.TestExtensions/job/GuestAgentDcrTest.Test/)
- Click `Build with Parameters'
- Add the `ReleaseTag`, Make sure its the same tag as the new tag added earlier
- Click on Build

NOTE: Only @larohra and @pagombar have permissions to create new builds as of now.
