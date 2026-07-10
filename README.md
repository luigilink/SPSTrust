# SPSTrust

![Latest release date](https://img.shields.io/github/release-date/luigilink/SPSTrust.svg?style=flat)
![Total downloads](https://img.shields.io/github/downloads/luigilink/SPSTrust/total.svg?style=flat)  
![Issues opened](https://img.shields.io/github/issues/luigilink/SPSTrust.svg?style=flat)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

## Description

SPSTrust is a PowerShell script tool to configure trust relationships between SharePoint
Server farms — exchanging STS/ROOT certificates, publishing service applications, granting
Topology and published service-application permissions, and connecting service application
proxies across farms.

It follows the Microsoft guidance [Share service applications across farms in SharePoint Server](https://learn.microsoft.com/en-us/sharepoint/administration/share-service-applications-across-farms)
and is compatible with all supported on-premises versions (SharePoint Server 2016 to
Subscription Edition).

[Download the latest release here!](https://github.com/luigilink/SPSTrust/releases/latest)

## Requirements

- PowerShell 5.1 or later
- CredSSP configured between the servers
- Administrative privileges on the SharePoint servers
- The **same** farm service account used across all farms being trusted

See the [Getting Started](https://github.com/luigilink/SPSTrust/wiki/Getting-Started) wiki page for details.

## Documentation

For usage, configuration, and getting-started information, visit the
[SPSTrust Wiki](https://github.com/luigilink/SPSTrust/wiki):

- [Getting Started](https://github.com/luigilink/SPSTrust/wiki/Getting-Started)
- [Configuration](https://github.com/luigilink/SPSTrust/wiki/Configuration)
- [Usage](https://github.com/luigilink/SPSTrust/wiki/Usage)
- [Release Process](https://github.com/luigilink/SPSTrust/wiki/Release-Process)

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md).
