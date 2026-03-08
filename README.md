# IOC → STIX 2.1 Converter for Microsoft Sentinel

Convert IOC lists (IPs, domains, URLs, hashes, emails, registry keys) to **STIX 2.1** format ready to import into **Microsoft Sentinel** Threat Intelligence.

Available in two versions with identical functionality:

| Version | File | Platform |
|---|---|---|
| PowerShell | `Convert-IOCsToSTIX.ps1` | Windows / PowerShell 5.1+ |
| Bash | `convert-iocs-to-stix.sh` | Linux / macOS / WSL |

---

## Features

- **Auto-detection** of IOC type — no manual classification needed
- **Deduplication** — case-insensitive, across all input files
- **TLP-aware** — embeds OASIS STIX 2.1 marking-definition IDs
- **Flexible input** — single file, folder, or multiple mixed formats
- **Split output** — one JSON per IOC type, or a single merged file
- **Config persistence** — defaults saved to `stix_converter_config.json`
- **API upload** — direct push to Sentinel TI API (optional)
- **Non-interactive mode** — suitable for cron jobs and pipelines
- **Logging** — optional output to log file

---

## Supported IOC Types

| STIX 2.1 Type | Detection | Output file (split mode) |
|---|---|---|
| `ipv4-addr` | IPv4 with optional CIDR | `stix_ipv4.json` |
| `ipv6-addr` | IPv6 with optional CIDR | `stix_ipv6.json` |
| `domain-name` | Valid hostname/domain | `stix_domains.json` |
| `url` | Starts with `http/https/ftp` | `stix_urls.json` |
| `file` | Hex hash — MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128) | `stix_hashes.json` |
| `email-addr` | Standard email format | `stix_emails.json` |
| `user-account` | `DOMAIN\user` or `user@host` patterns | `stix_users.json` |
| `windows-registry-key` | Starts with `HK` (HKLM, HKCU, etc.) | `stix_registry.json` |

---

## Supported Input Formats

| Extension | Description |
|---|---|
| `.txt` `.list` `.dat` `.ioc` | One value per line. Lines starting with `#`, `//` or `;` are treated as comments. |
| `.csv` | Auto-detects value column (`value`, `indicator`, `ioc`, `ip`, `domain`, `hash`, `url`). Also reads a date column if present (`date`, `first_seen`, `timestamp`). |
| `.json` | Array of objects. Auto-detects value field. Skips objects that are already STIX indicators. |
| Folder | Processes all supported files in the folder (non-recursive). |

---

## Requirements

### PowerShell version (`Convert-IOCsToSTIX.ps1`)

- **PowerShell 5.1** or **PowerShell 7+**
- No external modules required
- For API upload: network access to `sentinelus.azure-api.net`
- Execution policy must allow local scripts:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

If downloaded from the internet, unblock first:

```powershell
Unblock-File .\Convert-IOCsToSTIX.ps1
```

### Bash version (`convert-iocs-to-stix.sh`)

- **Bash 4.0+**
- **Python 3** (standard library only — no pip packages required)
- **curl** (only needed for API upload)

```bash
# Debian / Ubuntu
sudo apt install python3 curl

# RHEL / CentOS
sudo dnf install python3 curl
```

Make executable after download:

```bash
chmod +x convert-iocs-to-stix.sh
```

---

## Usage

### Interactive mode (menus)

```powershell
# PowerShell
.\Convert-IOCsToSTIX.ps1
```

```bash
# Bash
./convert-iocs-to-stix.sh
```

Both launch an interactive menu with 4 options:

```
  1. Convert file(s)
  2. Upload to Sentinel API
  3. Configuration
  4. Type detection test (single value)
  0. Exit
```

### Non-interactive / pipeline mode

```powershell
# PowerShell — convert a folder, split output by type
.\Convert-IOCsToSTIX.ps1 -InputPath .\iocs -OutputPath .\output -SplitByType

# PowerShell — single file, merged output
.\Convert-IOCsToSTIX.ps1 -InputPath .\indicators.txt -OutputPath .\output
```

```bash
# Bash — convert a folder, merged output (false = no split)
./convert-iocs-to-stix.sh /path/to/iocs /path/to/output false

# Bash — split by type
./convert-iocs-to-stix.sh /path/to/iocs /path/to/output true
```

---

## Menu walkthrough

### Option 1 — Convert file(s)

1. Enter a file path or folder path
2. Enter the output folder
3. Choose: single merged file or split by IOC type
4. Fill in metadata (or press Enter to use saved defaults):
   - Source name (e.g. `AlienVault`, `Unit42`)
   - Threat actor (e.g. `APT28`)
   - Tags (comma-separated)
   - Confidence (1–100)
   - TLP level (`white` / `green` / `amber` / `red`)
   - Indicator type (`malicious-activity`, `anomalous-activity`, `attribution`, `compromised`, `benign`, `unknown`)
   - Validity in days
5. Conversion runs and prints a summary
6. If the API is configured, offers to upload immediately

**Conversion summary example:**

```
  Input values   : 26
  Generated      : 25
  Duplicates     : 1
  Unknown/skip   : 0

  By type:
    file                       25

  Output file(s):
    → C:\Temp\output\stix_indicators.json
```

### Option 2 — Upload to Sentinel API

If the API is not yet configured, the tool detects this and offers to configure it inline without leaving the menu. You will be asked for:

- **Workspace ID** (GUID of your Sentinel workspace)
- **Batch size** (default: 100 indicators per request)
- **Bearer token** (entered as a secure/hidden input at upload time)

The Bearer token must belong to an account with the **Microsoft Sentinel Contributor** role on the workspace.

### Option 3 — Configuration

Saves defaults for all metadata fields and the API configuration to `stix_converter_config.json` in the same directory as the script. These defaults are used as pre-filled values in Option 1.

### Option 4 — Type detection test

Enter any value interactively to see how it would be classified and what STIX pattern would be generated. Useful for validating edge cases before a full conversion run.

```
  Value: 192.168.1.1
  → Detected: ipv4-addr    Pattern: [ipv4-addr:value = '192.168.1.1']

  Value: https://evil.com/payload
  → Detected: url          Pattern: [url:value = 'https://evil.com/payload']
```

---

## Output format

Each output file is a JSON array of STIX 2.1 indicator objects, compliant with the [Microsoft Sentinel Threat Intelligence import format](https://learn.microsoft.com/en-us/azure/sentinel/upload-indicators-api).

Example object:

```json
{
  "type": "indicator",
  "id": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "spec_version": "2.1",
  "pattern": "[ipv4-addr:value = '1.2.3.4']",
  "pattern_type": "stix",
  "pattern_version": "2.1",
  "created": "2026-03-08T12:00:00.000Z",
  "modified": "2026-03-08T12:00:00.000Z",
  "valid_from": "2026-03-08T12:00:00.000Z",
  "valid_until": "2027-03-08T12:00:00.000Z",
  "name": "MySource - 1.2.3.4",
  "description": "IOC (ipv4-addr) from MySource",
  "indicator_types": ["malicious-activity"],
  "revoked": false,
  "labels": ["ipv4-addr"],
  "confidence": 75,
  "lang": "en",
  "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
  "kill_chain_phases": [],
  "external_references": [],
  "granular_markings": [],
  "extensions": {}
}
```

> **Note:** `created_by_ref` is intentionally omitted. The STIX 2.1 spec defines it as optional, and Microsoft Sentinel rejects the object if it is present as an empty string.

---

## TLP marking-definition IDs (OASIS STIX 2.1)

| Level | Marking-definition ID |
|---|---|
| TLP:WHITE | `marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9` |
| TLP:GREEN | `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da` |
| TLP:AMBER | `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82` |
| TLP:RED | `marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed` |

---

## Configuration file

Both scripts persist configuration to `stix_converter_config.json` in the script directory:

```json
{
  "OutputFolder": "C:\\Temp\\output",
  "ThreatActor": "APT28",
  "Source": "AlienVault",
  "Tags": ["ransomware", "c2"],
  "Confidence": 80,
  "TLPLevel": "green",
  "IndicatorTypes": "malicious-activity",
  "ValidDays": 365,
  "LogFile": "",
  "API": {
    "Enabled": false,
    "WorkspaceId": "",
    "Endpoint": "https://sentinelus.azure-api.net/workspaces/{workspaceId}/threatintelligenceindicators:upload?api-version=2022-07-01",
    "BatchSize": 100
  }
}
```

---

## Importing into Microsoft Sentinel

1. Go to **Microsoft Sentinel** → **Threat Intelligence** → **Import**
2. Select **STIX** format
3. Upload the generated `.json` file

Or use the API upload built into the tool (Option 2), which calls the [Upload Indicators API](https://learn.microsoft.com/en-us/azure/sentinel/upload-indicators-api) directly.

---

## Known limitations

- `user-account` detection is basic — designed for `DOMAIN\user` patterns common in Windows environments
- The Sentinel TI API endpoint (`sentinelus`) may vary by region; update `Endpoint` in the config if needed
- API upload requires a Bearer token with **Microsoft Sentinel Contributor** role; token lifetime is not managed by the tool

---

## Author

**Alex Milla** — [alexmilla.net](https://alexmilla.net)
