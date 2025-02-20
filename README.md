# zns

zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value.

## Features

* Supports various DNS record types
* Colorized and tabular output for easy reading
* Concurrent queries for improved performance
* JSON output format for machine-readable results
* Option to write output to a file
* Option to query a specific DNS server

## Installing

```sh
brew install znscli/tap/zns
```

## Usage

```sh
$ zns example.com
A      example.com.   36m22s      93.184.215.14
NS     example.com.   22h27m45s   a.iana-servers.net.
NS     example.com.   22h27m45s   b.iana-servers.net.
SOA    example.com.   01h00m00s   ns.icann.org. noc.dns.icann.org.
MX     example.com.   22h00m56s   0 .
TXT    example.com.   24h00m00s   v=spf1 -all
TXT    example.com.   24h00m00s   wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn
AAAA   example.com.   17m11s      2606:2800:21f:cb07:6820:80da:af6b:8b2c
```

### Query a specific record type

```sh
$ zns example.com -q NS
NS   example.com.   21h13m27s   a.iana-servers.net.
NS   example.com.   21h13m27s   b.iana-servers.net.
```

### Use a specific DNS server

```sh
$ zns example.com -q NS --server 1.1.1.1
NS   example.com.   23h11m50s   a.iana-servers.net.
NS   example.com.   23h11m50s   b.iana-servers.net
```

### JSON output

```sh
$ zns example.com --json -q A | jq
{
  "@domain": "example.com",
  "@level": "info",
  "@message": "Successful query",
  "@record": "93.184.215.14",
  "@timestamp": "2024-12-17T01:04:06.104173+01:00",
  "@ttl": "33m10s",
  "@type": "A",
  "@version": "dev",
  "@view": "json"
}
...
```

### Writing to a file

```sh
export ZNS_LOG_FILE=/tmp/zns.log
$ zns example.com
```

## Contributing

Contributions are highly appreciated and always welcome.
Have a look through existing [Issues](https://github.com/znscli/zns/issues) and [Pull Requests](https://github.com/znscli/zns/pulls) that you could help with.

## License

This project is licensed under the MIT License. You are free to use, modify, and distribute the software, provided that you include the original license in any copies of the software. See the [LICENSE](LICENSE) file for more details.

