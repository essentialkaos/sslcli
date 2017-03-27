<p align="center"><a href="#usage-demo">Usage demo</a> • <a href="#installation">Installation</a> • <a href="#prebuilt-binaries">Prebuilt binaries</a> • <a href="#feature-list">Feature list</a> • <a href="#usage">Usage</a> • <a href="#build-status">Build Status</a> • <a href="#contributing">Contributing</a> • <a href="#terms-of-use">Terms of Use</a> • <a href="#license">License</a></p>

<p align="center">Command-line client for <a href="https://www.ssllabs.com">SSLLabs</a> public API.</p>

## Usage demo

[![demo](https://gh.kaos.io/sslcli-120.gif)](#usage-demo)

## Installation

Before the initial install allows git to use redirects for [pkg.re](https://github.com/essentialkaos/pkgre) service (reason why you should do this described [here](https://github.com/essentialkaos/pkgre#git-support)):

```
git config --global http.https://pkg.re.followRedirects true
```

To build the SSLScan Client from scratch, make sure you have a working Go 1.5+ workspace ([instructions](https://golang.org/doc/install)), then:

```
go get github.com/essentialkaos/sslcli
```

If you want update SSLScan Client to latest stable release, do:

```
go get -u github.com/essentialkaos/sslcli
```

## Prebuilt binaries

You can download prebuilt binaries for Linux and OS X from [EK Apps Repository](https://apps.kaos.io/sslcli/).

## Feature list

* Superb UI
* Output very similar to SSLLabs website output
* Checking many hosts at once
* Checking hosts defined in the file
* Check resumption
* JSON/XML/Text output for usage in third party services

## Usage

```
Usage: sslcli {options} host...

Options

  --format, -f text|json|yaml|xml    Output result in different formats
  --detailed, -d                     Show detailed info for each endpoint
  --ignore-mismatch, -i              Proceed with assessments on certificate mismatch
  --avoid-cache, -c                  Disable cache usage
  --public, -p                       Publish results on sslscan.com
  --perfect, -P                      Return non-zero exit code if not A+
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

  sslcli hosts.txt
  Check all hosts defined in hosts.txt file

```

## Build Status

| Branch | Status |
|------------|--------|
| `master` | [![Build Status](https://travis-ci.org/essentialkaos/sslcli.svg?branch=master)](https://travis-ci.org/essentialkaos/sslcli) |
| `develop` | [![Build Status](https://travis-ci.org/essentialkaos/sslcli.svg?branch=develop)](https://travis-ci.org/essentialkaos/sslcli) |

## Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/contributing-guidelines#contributing-guidelines).

## Terms of Use

This project is not affiliated with SSL Labs and not officially supported by SSL Labs. Before using this package please read [Qualys SSL Labs Terms of Use](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf).

Also you should:

* Only inspect sites and servers whose owners have given you permission to do so;
* Be clear that this tool works by sending assessment requests to remote SSL Labs servers and that this information will be shared with them.

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
