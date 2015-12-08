### SSLLabs Client

Command-line client for [SSLLabs](https://www.ssllabs.com) public API.

#### Usage demo

[![asciicast](https://asciinema.org/a/30736.png?r1)](https://asciinema.org/a/30736)

#### Installation

````
go get github.com/essentialkaos/ssllabs_client
````

#### Prebuilt binaries

You can download prebuilt binaries for Linux and OS X from [EK Apps Repository](https://apps.kaos.io/ssllabs-client/).

#### Feature list

* Superb UI
* Output very similar to SSLLabs website output
* Checking many hosts at once
* Checking hosts defined in file
* Check resumption
* Dev API support
* JSON/XML/Text output for usage in third party services

#### Usage

    Usage: ssllabs-client <options> host...
    
    Options:
    
      --format, -f text|json|xml    Output result in different formats
      --detailed, -d                Show detailed info for each endpoint
      --ignore-mismatch, -i         Proceed with assessments on certificate mismatch
      --cache, -c                   Use cache if possible
      --dev-api, -D                 Use dev API instead production
      --private, -p                 Don't public results on ssllabs
      --perfect, -P                 Return non-zero exit code if not A+
      --notify, -n                  Notify when check is done
      --quiet, -q                   Don't show any output
      --no-color, -nc               Disable colors in output
      --help, -h                    Show this help message
      --version, -v                 Show version

#### Build Status

| Repository | Status |
|------------|--------|
| Stable | [![Build Status](https://travis-ci.org/essentialkaos/ssllabs_client.svg?branch=master)](https://travis-ci.org/essentialkaos/ssllabs_client) |
| Unstable | [![Build Status](https://travis-ci.org/essentialkaos/ssllabs_client.svg?branch=develop)](https://travis-ci.org/essentialkaos/ssllabs_client) |

#### License

[EKOL](https://essentialkaos.com/ekol)
