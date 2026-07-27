# zns

zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value.

## Features

* Supports all DNS record types
* Colorized and tabular output for easy reading
* Concurrent queries for improved performance
* JSON output format for machine-readable results
* Option to write output to a file
* Option to query a specific DNS server

## Installing

### Homebrew

```sh
brew install zns
```

### MacPorts

```sh
port install zns
```

### FreeBSD

```sh
pkg install zns
```

## Usage

```sh
$ zns google.com
A       google.com.   01m35s   142.250.180.14
AAAA    google.com.   02m35s   2a00:1450:400e:808::200e
CAA     google.com.   05m07s   0 issue pki.goog
HTTPS   google.com.   50m03s   1 . alpn="h2,h3"
MX      google.com.   01m47s   10 smtp.google.com.
NS      google.com.   50m03s   ns1.google.com.
NS      google.com.   50m03s   ns2.google.com.
SOA     google.com.   01m00s   ns1.google.com. dns-admin.google.com.
TXT     google.com.   49s      v=spf1 include:_spf.google.com ~all
TXT     google.com.   49s      google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o
...
```

### Query a specific record type

Any DNS record type can be queried, e.g. `-q NS`, `-q CAA`, `-q DNSKEY`, or `-q HTTPS`.

```sh
$ zns google.com -q HTTPS
HTTPS   google.com.   50m03s   1 . alpn="h2,h3"
```

### Query multiple record types

Types can be passed as bare arguments, comma-separated, or by repeating the flag. Results render in the requested order.

```sh
$ zns google.com CAA HTTPS
CAA     google.com.   05m07s   0 issue pki.goog
HTTPS   google.com.   50m02s   1 . alpn="h2,h3"
```

### Use a specific DNS server

```sh
$ zns google.com -q NS --server 1.1.1.1
NS   google.com.   50m03s   ns1.google.com.
NS   google.com.   50m03s   ns2.google.com.
```

### JSON output

```sh
$ zns google.com --json -q A | jq
{
  "domain": "google.com",
  "level": "info",
  "message": "Successful query",
  "record": "142.250.180.14",
  "timestamp": "2026-07-27T22:03:32.246721+02:00",
  "ttl": "01m35s",
  "type": "A",
  "version": "dev",
  "view": "json"
}
```

### Writing to a file

```sh
export ZNS_LOG_FILE=/tmp/zns.log
$ zns google.com
```

## Contributing

Contributions are highly appreciated and always welcome.
Have a look through existing [Issues](https://github.com/znscli/zns/issues) and [Pull Requests](https://github.com/znscli/zns/pulls) that you could help with.

## License

This project is licensed under the MIT License. You are free to use, modify, and distribute the software, provided that you include the original license in any copies of the software. See the [LICENSE](LICENSE) file for more details.
