#!/usr/bin/env bash

version=$(grep '^AGENT_VERSION' "$(Build.SourcesDirectory)/azurelinuxagent/common/version.py" |  sed "s/.*'\([^']\+\)'.*/\1/")
echo "##vso[task.setvariable variable=agentVersion]$version"
sudo ./makepkg.py
sudo cp ./eggs/WALinuxAgent-$version.zip "$(Build.SourcesDirectory)/dcr"