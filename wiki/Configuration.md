# Configuration

To customize the script for your environment, you need to prepare a JSON configuration file. Below is a sample structure for the file:

```json
{
  "$schema": "http://json-schema.org/schema#",
  "contentVersion": "1.0.0.0",
  "ConfigurationName": "PROD",
  "ApplicationName": "contoso",
  "Domain": "contoso.com",
  "CertFileShared": "\\\\srvfileshared.contoso.com\\certsfolder",
  "Trusts": [
    {
      "LocalFarm": "SEARCH",
      "RemoteFarms": ["CONTENT", "SERVICES"],
      "Services": ["CONTOSOPRODSCH"]
    },
    {
      "LocalFarm": "SERVICES",
      "RemoteFarms": ["CONTENT", "SEARCH"],
      "Services": ["CONTOSOPRODUPS", "CONTOSOPRODMMS", "CONTOSOPRODSSA"]
    },
    {
      "LocalFarm": "CONTENT",
      "RemoteFarms": ["SEARCH", "SERVICES"],
      "Services": ["Content"]
    }
  ],
  "Farms": [
    {
      "Name": "SEARCH",
      "Server": "srvcontososearch"
    },
    {
      "Name": "SERVICES",
      "Server": "srvcontososervices"
    },
    {
      "Name": "CONTENT",
      "Server": "srvcontosocontent"
    }
  ]
}
```

## Configuration and Application

`ConfigurationName` is used to populate the content of `Environment` PowerShell Variable.
`ApplicationName` is used to populate the content of `Application` PowerShell Variable.

## Certificate Configuration

Certificate File Shared Path: `\\srvfileshared.contoso.com\certsfolder`

The certificate file is stored in a shared folder, accessible to all relevant servers, ensuring secure communication across the server farms.

> [!IMPORTANT]
> The credential used in the FarmAccount parameter needs write permission on this file share

## Trust Relationships

This configuration defines specific trust relationships between different server farms in the PROD environment. Each trust relationship specifies a local farm, the remote farms it trusts, and the services available to those farms.

### Trust Definitions

1. **SEARCH Farm**

   - **Trusted Remote Farms**: `CONTENT`, `SERVICES`
   - **Exposed Services**: `CONTOSOPRODSCH`

2. **SERVICES Farm**

   - **Trusted Remote Farms**: `CONTENT`, `SEARCH`
   - **Exposed Services**:
     - `CONTOSOPRODUPS` (User Profile Service)
     - `CONTOSOPRODMMS` (Managed Metadata Service)
     - `CONTOSOPRODSSA` (Search Service Application)

3. **CONTENT Farm**
   - **Trusted Remote Farms**: `SEARCH`, `SERVICES`
   - **Exposed Service**: `Content`

These trust relationships allow each farm to communicate securely with one another, sharing specific services as needed.

> [!IMPORTANT]
> You need to use the same service account to configure trust between farms

## Farm Server Details

Each farm is associated with a dedicated server, as outlined below:

| Farm Name | Server Name        |
| --------- | ------------------ |
| SEARCH    | srvcontososearch   |
| SERVICES  | srvcontososervices |
| CONTENT   | srvcontosocontent  |

These servers are configured to handle specific workloads as per their assigned farm roles.

## Notes

- File Path Format: Ensure that the file path syntax (`\\`) is correctly configured for shared network access.
- Farm Names: The `LocalFarm` and `RemoteFarms` properties should match the Farms names exactly to maintain trust relationships.
- Service Availability: Each farm's services are restricted to only trusted farms as specified, ensuring a secure, segmented setup for production use.

## Next Step

For the next steps, go to the [Usage](./Usage) page.
