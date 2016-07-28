<p align="center"><a href="#usage-demo">Usage demo</a> • <a href="#installation">Installation</a> • <a href="#prebuilt-binaries">Prebuilt binaries</a> • <a href="#feature-list">Feature list</a> • <a href="#usage">Usage</a> • <a href="#build-status">Build Status</a> • <a href="#contributing">Contributing</a> • <a href="#license">License</a></p>

# SSLLabs Client

Command-line client for [SSLLabs](https://www.ssllabs.com) public API.

## Usage demo

[![asciicast](https://asciinema.org/a/30736.png?r1)](https://asciinema.org/a/30736)

## Installation

To build the SSLLabs Client from scratch, make sure you have a working Go 1.5+ workspace ([instructions](https://golang.org/doc/install)), then:

```
go get github.com/essentialkaos/ssllabs_client
```

If you want update SSLLabs Client to latest stable release, do:

```
go get -u github.com/essentialkaos/ssllabs_client
```

## Prebuilt binaries

You can download prebuilt binaries for Linux and OS X from [EK Apps Repository](https://apps.kaos.io/ssllabs-client/).

## Feature list

* Superb UI
* Output very similar to SSLLabs website output
* Checking many hosts at once
* Checking hosts defined in file
* Check resumption
* Dev API support
* JSON/XML/Text output for usage in third party services

## Usage

````
Usage: ssllabs-client {options} host...

Options:

  --format, -f text|json|xml    Output result in different formats
  --detailed, -d                Show detailed info for each endpoint
  --ignore-mismatch, -i         Proceed with assessments on certificate mismatch
  --cache, -c                   Use cache if possible
  --public, -p                  Publish results on ssllabs.com
  --perfect, -P                 Return non-zero exit code if not A+
  --notify, -n                  Notify when check is done
  --quiet, -q                   Don't show any output
  --no-color, -nc               Disable colors in output
  --help, -h                    Show this help message
  --version, -v                 Show version

Examples:

  ssllabs-client google.com
  Check google.com

  ssllabs-client -P google.com
  Check google.com and return zero exit code only if result is perfect (A+)

  ssllabs-client -p -c google.com
  Check google.com, publish results, use cache

  ssllabs-client hosts.txt
  Check all hosts defined in hosts.txt file

````

## Build Status

| Repository | Status |
|------------|--------|
| Stable | [![Build Status](https://travis-ci.org/essentialkaos/ssllabs_client.svg?branch=master)](https://travis-ci.org/essentialkaos/ssllabs_client) |
| Unstable | [![Build Status](https://travis-ci.org/essentialkaos/ssllabs_client.svg?branch=develop)](https://travis-ci.org/essentialkaos/ssllabs_client) |

## Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/contributing-guidelines#contributing-guidelines).

## License

[EKOL](https://essentialkaos.com/ekol)
