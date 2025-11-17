# Windows ADMX Parser

This tool scans a Windows PolicyDefinitions directory (ADMX/ADML) and exports every policy definition into a structured JSON or YAML file. This was made for being able to quickly search for any string in LGPE to see the data/value/key/description. I personally used it in the [win-config](https://github.com/5Noxi/win-config) project for several options. This small parser project was inspired by the [WindowsAdmxParser](https://github.com/innovatodev/WindowsAdmxParser) powershell module. However, since it's not entirely correct (sometimes `KeyName` is displayed instead of `ValueName`), the class is not inserted directly into `KeyPath` and `KeyNames` is not inserted directly into `KeyPath`.

> [!CAUTION]
> An issue that occurred while creating the parser is that a value was defined outside of `Elements` and the same value was defined again in `Elements`. Elements does not contain any data for the value outside the elements list, which is handled in the tool by adding the value to the end of the keypath. However, there're isolated cases where this isn't correct (so far only where both values had the same names). I've currently solved this by deleting the upper value.

## Features

- Automatically discovers language folders, or use `--language` to use specific ones.
- Supports ignoring specific ADMX files, filtering by policy class (`Machine`/`User`), category name, or free-text policy search.
- Generates pretty JSON (or YAML) by default, `--compress` only affects JSON exports.

## Requirements

- Python 3.8+
- `pip install pyyaml` for YAML output

## Usage

```powershell
python admx-parser.py [OPTIONS]
```

### CLI Flags

| Flag | Description | Default |
| --- | --- | --- |
| `-d, --definitions PATH` | PolicyDefinitions directory | `C:\Windows\PolicyDefinitions` |
| `-l, --language LANG` | Include a language folder (repeatable) | Auto-detected + `en-US` |
| `-i, --ignore NAME` | Ignore an ADMX base name (repeatable) | None |
| `--class {Machine,User}` | Restrict to policy class (repeatable) | All |
| `--category TEXT` | Filter by category substring | None |
| `--policy TEXT` | Filter by policy/display name substring | None |
| `--include-obsolete` | Include obsolete/deprecated policies | Off |
| `--format {json,yaml}` | Output format | `json` |
| `--compress` | Write minified JSON (ignored for YAML) | Pretty |
| `--output PATH` | Custom destination file | `Policies.json`/`Policies.yaml` (in current dir) |
| `-h, --help` | Shows flags from above | - |

### Examples

```powershell
# Default (pretty JSON)
python admx-parser.py

# YAML output, ignore inetres and WindowsUpdate ADMX files
python admx-parser.py --format yaml --ignore inetres --ignore WindowsUpdate

# Machine-only policies under the Edge category, compressed JSON
python admx-parser.py --class Machine --category Edge --compress
```

## Output Structure

> [assets\Policies.json](https://github.com/5Noxi/admx-parser/blob/main/assets/Policies.json)  
> [assets\Policies.yaml](https://github.com/5Noxi/admx-parser/blob/main/assets/Policies.yaml)

```json
{
  "File": "AppPrivacy.admx",
  "CategoryName": "AppPrivacy",
  "PolicyName": "LetAppsAccessAccountInfo",
  "NameSpace": "Microsoft.Policies.AppPrivacy",
  "Supported": "Windows_10_0",
  "DisplayName": "Let Windows apps access account information",
  "ExplainText": "This policy setting specifies whether Windows apps can access account
    information...",
  "KeyPath": [
    "HKLM\\Software\\Policies\\Microsoft\\Windows\\AppPrivacy"
  ],
  "Elements": [
    { "Type": "Enum", "ValueName": "LetAppsAccessAccountInfo", "Items": [
        { "DisplayName": "User is in control", "Data": "0" },
        { "DisplayName": "Force Allow", "Data": "1" },
        { "DisplayName": "Force Deny", "Data": "2" }
      ]
    }
  ]
},
```
```yaml
- File: AppPrivacy.admx
  CategoryName: AppPrivacy
  PolicyName: LetAppsAccessAccountInfo
  NameSpace: Microsoft.Policies.AppPrivacy
  Supported: Windows_10_0
  DisplayName: Let Windows apps access account information
  ExplainText: This policy setting specifies whether Windows apps can access account
    information...
  KeyPath:
  - HKLM\Software\Policies\Microsoft\Windows\AppPrivacy
  Elements:
  - Type: Enum
    ValueName: LetAppsAccessAccountInfo
    Items:
    - DisplayName: User is in control
      Data: '0'
    - DisplayName: Force Allow
      Data: '1'
    - DisplayName: Force Deny
      Data: '2'
```