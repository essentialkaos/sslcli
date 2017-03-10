########################################################################################

.PHONY = fmt all clean deps

########################################################################################

all: sslcli

sslcli:
	go build sslcli.go

deps:
	go get -v pkg.re/essentialkaos/ek.v7
	go get -v pkg.re/essentialkaos/sslscan.v5

fmt:
	find . -name "*.go" -exec gofmt -s -w {} \;

clean:
	rm -f sslcli

########################################################################################

