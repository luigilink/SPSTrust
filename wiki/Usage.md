# Usage

## Parameters

| Parameter        | Description                                       |
| ---------------- | ------------------------------------------------- |
| `-ConfigFile`    | Specifies the path to the configuration file.     |
| `-FarmAccount`   | Specifies the service account who runs the script |
| `-CleanServices` | Remove published services on each trusted farm    |

### Basic Usage Example

Run the script with a specified configuration and farm account:

```powershell
.\SPSWeather.ps1 -ConfigFile 'contoso-PROD.json' -FarmAccount (Get-Credential)
```

### Clean Services Usage Example

Remove published services on each trusted farm:

```powershell
.\SPSWeather.ps1 -ConfigFile 'contoso-PROD.json' -CleanServices
```
