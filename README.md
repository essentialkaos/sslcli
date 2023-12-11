<p align="center"><a href="#readme"><img src="https://gh.kaos.st/sslcli.svg"/></a></p>

<p align="center">
  <a href="https://kaos.sh/w/sslcli/ci"><img src="https://kaos.sh/w/sslcli/ci.svg" alt="GitHub Actions CI Status" /></a>
  <a href="https://kaos.sh/r/sslcli"><img src="https://kaos.sh/r/sslcli.svg" alt="GoReportCard" /></a>
  <a href="https://kaos.sh/b/sslcli"><img src="https://kaos.sh/b/edc52bb1-c807-470b-8466-b86cc0cfcdbe.svg" alt="codebeat badge" /></a>
  <a href="https://kaos.sh/w/sslcli/codeql"><img src="https://kaos.sh/w/sslcli/codeql.svg" alt="GitHub Actions CodeQL Status" /></a>
  <a href="#license"><img src="https://gh.kaos.st/apache2.svg"></a>
</p>

<p align="center"><a href="#usage-demo">Usage demo</a> • <a href="#installation">Installation</a> • <a href="#feature-list">Feature list</a> • <a href="#usage">Usage</a> • <a href="#build-status">Build Status</a> • <a href="#contributing">Contributing</a> • <a href="#terms-of-use">Terms of Use</a> • <a href="#license">License</a></p>

<br/>

`sslcli` is command-line client for <a href="https://www.ssllabs.com">SSLLabs</a> public API.

**IMPORTANT:** Currently, SSLLabs API doesn't provide same info as SSLLabs website.

### Usage demo

[![demo](https://gh.kaos.st/sslcli-275.gif)](#usage-demo)

### Installation

#### From source

To build the SSLScan Client from scratch, make sure you have a working Go 1.19+ workspace ([instructions](https://go.dev/doc/install)), then:

```
go install github.com/essentialkaos/sslcli@latest
```

#### From [ESSENTIAL KAOS Public Repository](https://kaos.sh/kaos-repo)

```bash
sudo yum install -y https://pkgs.kaos.st/kaos-repo-latest.el$(grep 'CPE_NAME' /etc/os-release | tr -d '"' | cut -d':' -f5).noarch.rpm
sudo yum install sslcli
```

#### Prebuilt binaries

You can download prebuilt binaries for Linux and macOS from [EK Apps Repository](https://apps.kaos.st/sslcli/latest):

```bash
bash <(curl -fsSL https://apps.kaos.st/get) sslcli
```

#### Container Image

The latest version of `sslcli` also available as container image on [GitHub Container Registry](https://kaos.sh/p/sslcli) and [Docker Hub](https://kaos.sh/d/sslcli):

```bash
podman run --rm -it ghcr.io/essentialkaos/sslcli:latest mydomain.com
# or
docker run --rm -it ghcr.io/essentialkaos/sslcli:latest mydomain.com
```

### Feature list

* Superb UI
* Output very similar to SSLLabs website output
* Checking many hosts at once
* Checking hosts defined in the file
* Check resumption
* JSON/XML/YAML/Text output for usage in third party scripts

### Usage

```
Usage: sslcli {options} host…

Options

  --format, -f text|json|yaml|xml    Output result in different formats
  --detailed, -d                     Show detailed info for each endpoint
  --ignore-mismatch, -i              Proceed with assessments on certificate mismatch
  --avoid-cache, -c                  Disable cache usage
  --public, -p                       Publish results on sslscan.com
  --perfect, -P                      Return non-zero exit code if not A+
  --max-left, -M duration            Check expiry date (num + d/w/m/y)
  --notify, -n                       Notify when check is done
  --quiet, -q                        Don't show any output
  --no-color, -nc                    Disable colors in output
  --help, -h                         Show this help message
  --version, -v                      Show version

Examples

  sslcli google.com
  Check google.com

  sslcli -P google.com
  Check google.com and return zero exit code only if result is perfect (A+)

  sslcli -p -c google.com
  Check google.com, publish results, disable cache usage

  sslcli -M 3m -q google.com
  Check google.com in quiet mode and return error if cert expire in 3 months

  sslcli hosts.txt
  Check all hosts defined in hosts.txt file
```

### Build Status

| Branch | Status |
|------------|--------|
| `master` | [![CI](https://kaos.sh/w/sslcli/ci.svg?branch=master)](https://kaos.sh/w/sslcli/ci?query=branch:master) |
| `develop` | [![CI](https://kaos.sh/w/sslcli/ci.svg?branch=develop)](https://kaos.sh/w/sslcli/ci?query=branch:develop) |

### Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/contributing-guidelines#contributing-guidelines).

### Terms of Use

This project is not affiliated with SSL Labs and not officially supported by SSL Labs. Before using this package please read [Qualys SSL Labs Terms of Use](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf).

Also you should:

* Only inspect sites and servers whose owners have given you permission to do so;
* Be clear that this tool works by sending assessment requests to remote SSL Labs servers and that this information will be shared with them.

### License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

<p align="center"><a href="https://essentialkaos.com"><img src="https://gh.kaos.st/ekgh.svg"/></a></p>
