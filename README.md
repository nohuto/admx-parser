# Windows ADMX Parser

This tool scans a Windows PolicyDefinitions directory (ADMX/ADML) and exports every policy definition into a structured JSON or YAML file. This was made for being able to quickly search for any string in LGPE to see the data/value/key/description. I personally used it in the [win-config](https://github.com/5Noxi/win-config) project for several options. This small parser project was inspired by the [WindowsAdmxParser](https://github.com/innovatodev/WindowsAdmxParser) powershell module.

## Features

- Automatically discovers language folders, or use `--language` to use specific ones.
- Supports ignoring specific ADMX files, filtering by policy class (`Machine`/`User`), category name, or free-text policy search.
- Generates pretty JSON (or YAML) by default, `--compress` only affects JSON exports.

## Requirements

- Python 3.8+
- `pip install pyyaml` for YAML output

## Usage

```ps
python admx_parser.py [OPTIONS]
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

```ps
# Default (pretty JSON)
python admx_parser.py

# YAML output, ignore inetres and WindowsUpdate ADMX files
python admx_parser.py --format yaml --ignore inetres --ignore WindowsUpdate

# Machine-only policies under the Edge category, compressed JSON
python admx_parser.py --class Machine --category Edge --compress
```

## Output Structure

> [assets\Policies.json]()  
> [assets\Policies.yaml]()

```json
{
  "File": "AccountNotifications.admx",
  "CategoryName": "AccountNotifications",
  "PolicyName": "DisableAccountNotifications",
  "NameSpace": "Microsoft.Policies.AccountNotifications",
  "Supported": "Windows_10_0_20H1_NOSERVER",
  "DisplayName": "Turn off account notifications in Start",
  "ExplainText": "This policy allows you to prevent Windows from displaying notifications
    to Microsoft account (MSA) [...]",
  "KeyPath": [
    "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AccountNotifications"
  ],
  "ValueName": "DisableAccountNotifications",
  "Elements": [
    {
      "Type": "EnabledValue",
      "Value": "1"
    },
    {
      "Type": "DisabledValue",
      "Value": "0"
    }
  ]
},
```
```yaml
- File: AccountNotifications.admx
  CategoryName: AccountNotifications
  PolicyName: DisableAccountNotifications
  NameSpace: Microsoft.Policies.AccountNotifications
  Supported: Windows_10_0_20H1_NOSERVER
  DisplayName: Turn off account notifications in Start
  ExplainText: 'This policy allows you to prevent Windows from displaying notifications
    to Microsoft account (MSA) [...]'
  KeyPath:
  - HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications
  ValueName: DisableAccountNotifications
  Elements:
  - Type: EnabledValue
    Value: '1'
  - Type: DisabledValue
    Value: '0'
```