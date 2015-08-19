### Building the walinuxagent snap package

1. You will need the snappy developer tools on your Ubuntu Developer Desktop:

        $ sudo add-apt-repository ppa:snappy-dev/tools
        $ sudo apt-get update
        $ sudo apt-get upgrade
        $ sudo apt-get install snappy-tools

2. Copy the azurelinuxagent folder to snappy/lib

        $ cp -rf azurelinuxagent snappy/lib
	
3. Build the snap package under the snappy folder

        $ cd snappy
        $ snappy build 