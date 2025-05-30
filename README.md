<p align="center"><a href="#readme"><img src=".github/images/card.svg"/></a></p>

<p align="center">
  <a href="https://kaos.sh/r/sslcli"><img src="https://kaos.sh/r/sslcli.svg" alt="GoReportCard" /></a>
  <a href="https://kaos.sh/y/sslcli"><img src="https://kaos.sh/y/cb0c9951ae5c4ac89ea6192e9bfb170f.svg" alt="Codacy badge" /></a>
  <a href="https://kaos.sh/w/sslcli/ci-push"><img src="https://kaos.sh/w/sslcli/ci-push.svg" alt="GitHub Actions CI Status" /></a>
  <a href="https://kaos.sh/w/sslcli/codeql"><img src="https://kaos.sh/w/sslcli/codeql.svg" alt="GitHub Actions CodeQL Status" /></a>
  <a href="#license"><img src=".github/images/license.svg"/></a>
</p>

<p align="center"><a href="#usage-demo">Usage demo</a> • <a href="#installation">Installation</a> • <a href="#feature-list">Feature list</a> • <a href="#usage">Usage</a> • <a href="#ci-status">CI Status</a> • <a href="#contributing">Contributing</a> • <a href="#terms-of-use">Terms of Use</a> • <a href="#license">License</a></p>

<br/>

`sslcli` is command-line client for <a href="https://www.ssllabs.com">Qualys SSL Labs</a> public API.

> [!CAUTION]
> Currently, the SSL Labs API doesn't provide the same information as the [SSL Labs website](https://www.ssllabs.com/ssltest/).

### Usage demo

[![demo](https://github.com/user-attachments/assets/924631d8-5a53-4e86-9728-bf86569aee14)](#usage-demo)

### Installation

#### From source

To build the SSLScan Client from scratch, make sure you have a working Go [1.23+](https://github.com/essentialkaos/.github/blob/master/GO-VERSION-SUPPORT.md) workspace ([instructions](https://go.dev/doc/install)), then:

```
go install github.com/essentialkaos/sslcli/v3@latest
```

#### From [ESSENTIAL KAOS Public Repository](https://kaos.sh/kaos-repo)

```bash
sudo dnf install -y https://pkgs.kaos.st/kaos-repo-latest.el$(grep 'CPE_NAME' /etc/os-release | tr -d '"' | cut -d':' -f5).noarch.rpm
sudo dnf install sslcli
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

<img src=".github/images/usage.svg" />

### CI Status

| Branch | Status |
|------------|--------|
| `master` | [![CI](https://kaos.sh/w/sslcli/ci-push.svg?branch=master)](https://kaos.sh/w/sslcli/ci-push?query=branch:master) |
| `develop` | [![CI](https://kaos.sh/w/sslcli/ci-push.svg?branch=develop)](https://kaos.sh/w/sslcli/ci-push?query=branch:develop) |

### Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/.github/blob/master/CONTRIBUTING.md).

### Terms of Use

This project is not affiliated with SSL Labs and not officially supported by SSL Labs. Before using this package please read [Qualys SSL Labs Terms of Use](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf).

Also you should:

* Only inspect sites and servers whose owners have given you permission to do so;
* Be clear that this tool works by sending assessment requests to remote SSL Labs servers and that this information will be shared with them.

### License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

<p align="center"><a href="https://kaos.dev"><img src="https://raw.githubusercontent.com/essentialkaos/.github/refs/heads/master/images/ekgh.svg"/></a></p>
