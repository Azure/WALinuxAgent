# Contributing to Linux Guest Agent
First, thank you for contributing to WALinuxAgent repository!

## Basics
If you would like to become an active contributor to this project, please follow the instructions provided in [Microsoft Azure Projects Contribution Guidelines](http://azure.github.io/guidelines/).

## Table of Contents
[Before starting](#before-starting)
- [Github basics](#github-basics)
- [Code of Conduct](#code-of-conduct)

[Making Changes](#making-changes)
- [Pull Requests](#pull-requests)
- [Pull Request Guidelines](#pull-request-guidelines)
    - [Cleaning up commits](#cleaning-up-commits)
    - [General guidelines](#general-guidelines)
    - [Testing guidelines](#testing-guidelines)

## Before starting

### Github basics

#### GitHub workflow

If you don't have experience with Git and Github, some of the terminology and process can be confusing. [Here's a guide to understanding Github](https://guides.github.com/introduction/flow/).

#### Forking the Azure/Guest-Configuration-Extension repository

Unless you are working with multiple contributors on the same file, we ask that you fork the repository and submit your Pull Request from there. [Here's a guide to forks in Github](https://guides.github.com/activities/forking/).

### Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Making Changes

### Pull Requests

You can find all of the pull requests that have been opened in the [Pull Request](https://github.com/Azure/Guest-Configuration-Extension/pulls) section of the repository.

To open your own pull request, click [here](https://github.com/Azure/WALinuxAgent/compare). When creating a pull request, keep the following in mind:
- Make sure you are pointing to the fork and branch that your changes were made in
- Choose the correct branch you want your pull request to be merged into
- The pull request template that is provided **should be filled out**; this is not something that should just be deleted or ignored when the pull request is created
    - Deleting or ignoring this template will elongate the time it takes for your pull request to be reviewed
<!-- - The SLA for reviewing pull requests is **two business days** -->

### Pull Request Guidelines

A pull request template will automatically be included as a part of your PR. Please fill out the checklist as specified. Pull requests **will not be reviewed** unless they include a properly completed checklist.

#### Cleaning up Commits

If you are thinking about making a large change, **break up the change into small, logical, testable chunks, and organize your pull requests accordingly**.

Often when a pull request is created with a large number of files changed and/or a large number of lines of code added and/or removed, GitHub will have a difficult time opening up the changes on their site. This forces the Azure Guest-Configuration-Extension team to use separate software to do a code review on the pull request.

If you find yourself creating a pull request and are unable to see all the changes on GitHub, we recommend **splitting the pull request into multiple pull requests that are able to be reviewed on GitHub**.

If splitting up the pull request is not an option, we recommend **creating individual commits for different parts of the pull request, which can be reviewed individually on GitHub**.

For more information on cleaning up the commits in a pull request, such as how to rebase, squash, and cherry-pick, click [here](https://github.com/Azure/azure-powershell/blob/dev/documentation/cleaning-up-commits.md).

#### General guidelines

The following guidelines must be followed in **EVERY** pull request that is opened.

- Title of the pull request is clear and informative
- There are a small number of commits that each have an informative message
- A description of the changes the pull request makes is included, and a reference to the issue being resolved, if the change address any
- All files have the Microsoft copyright header

#### Testing Guidelines

The following guidelines must be followed in **EVERY** pull request that is opened.

- Pull request includes test coverage for the included changes