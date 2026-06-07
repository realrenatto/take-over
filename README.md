# Take-Over
Take-Over is a Go-based tool designed to detect subdomain takeover vulnerabilities across different Cloud Service Providers (CSPs).

## Installation

```bash
https://github.com/realrenatto/take-over.git
cd take-over
```

Linux/macOS:
```bash
go mod tidy
go build -o take-over .
```

Windows:
```bash
go mod tidy
go build -o take-over.exe .
```

## Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target URL/host to scan. |
| `-l`, `--list` | Path to file containing a list of target URLs/hosts to scan (one per line). |
| `-c`, `--concurrency` | Maximum number of targets to be executed in parallel (default 10). |
| `-o`, `--output` | Output file to write found issues/vulnerabilities. |
| `-v`, `--verbose` | Show both vulnerable and non-vulnerable subdomains. |
| `-h`, `--help` | Show help. |

You must specify at least one of the following flags:

`-u`, `--url` — Target URL/host to scan.

`-l`, `--list` — Path to a file containing a list of target URLs/hosts to scan (one per line).

## Usage

### Target Specification

#### Scan a Single Target

```bash
take-over -u example.example.com
```

#### Scan Multiple Targets from a File

```bash
take-over -l list.txt
```

The file must contain one target per line:

```text
http://example.example.com
m.facebook.com
https://ishouldnotexist.wordpress.com
```

### Output Control

By default, Take-Over displays only vulnerable subdomains.

To display both vulnerable and non-vulnerable results, use the verbose flag:

```bash
take-over -l list.txt -v
```