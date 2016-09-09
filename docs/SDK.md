# SDK Architecture Design

## Goal
To build an entry point script along with a collection of tools and automation that enables users to deploy Storj services. This deployment would be anything ranging from a local deployment of a single service to a full production cluster in a remote cloud infrastructure.

## Start Here
There will be a single script for all linux type OS's that will provide you with options as to what you would like to do and will walk you through the process. This script should be smart enough to let you knwo whats wrong when it runs into errors or issues with your local setup regarding keys for cloud providers, docker availability, etc...

This script could start out looking something like this...
```
Hello, welcome to Storj Automation. Please choose your direction…

1) Development
1a) Deploy a single service locally
1b) Deploy a full cluster locally
2) Production
1a) Deploy a single service to a cloud provider
1b) Deploy a full cluster to a cloud provider
```

## Use Cases
  + I am a developer and I would like to help fix a bug in the farmer code. I do not need to run an entire cluster locally. I should be able to run tests against it and possibly have some preset scripted tests to run against it to help troubleshoot and test manually.
  + I am a sysadmin and I want to deploy a full cluster to run in production for our business.

### Features
  + Deploy to local
    + Methods
      + Docker
        + This could use Chef & BigBang to set up your local docker services if they are not already set up
      + Native NodeJS (Using Chef & BigBang)
        + This could use the existing Chef recipes to fully set up the services and BigBang to run it all locally
    + Services
      + CLI
      + Single service
      + Full Cluster
    + Configuragion
      + Testing network
      + Production network
