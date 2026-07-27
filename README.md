# zns

zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value.

## Features

* Supports all DNS record types, with rich formatting for A, AAAA, AFSDB, CAA, CDNSKEY, CDS, CERT, CNAME, DHCID, DNAME, DNSKEY, DS, HINFO, HTTPS, KX, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, PTR, RP, RRSIG, SMIMEA, SOA, SPF, SRV, SSHFP, SVCB, TLSA, TXT, URI, and ZONEMD; any other record type is rendered in its zone-file presentation
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
```
port install zns
```

### FreeBSD
```
pkg install zns
```

## Usage

```sh
$ zns example.com
A         example.com.   03m31s      172.66.147.243
A         example.com.   03m31s      104.20.23.154
AAAA      example.com.   05s         2606:4700:10::6814:179a
AAAA      example.com.   05s         2606:4700:10::ac42:93f3
CDNSKEY   example.com.   01h00m00s   257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
CDS       example.com.   01h00m00s   2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A
DNSKEY    example.com.   28m05s      256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
DNSKEY    example.com.   28m05s      257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
DS        example.com.   53m12s      2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A
HTTPS     example.com.   02m33s      1 . alpn="h2" ipv4hint="104.20.23.154,172.66.147.243" ipv6hint="2606:4700:10::6814:179a,2606:4700:10::ac42:93f3"
MX        example.com.   05m00s      0 .
NS        example.com.   43m34s      elliott.ns.cloudflare.com.
NS        example.com.   43m34s      hera.ns.cloudflare.com.
NSEC      example.com.   30m00s      \000.example.com. A NS SOA PTR HINFO MX TXT AAAA LOC SRV NAPTR CERT SSHFP RRSIG NSEC DNSKEY TLSA SMIMEA HIP CDS CDNSKEY OPENPGPKEY SVCB HTTPS URI CAA
SOA       example.com.   12m53s      elliott.ns.cloudflare.com. dns.cloudflare.com.
TXT       example.com.   05m00s      v=spf1 -all
TXT       example.com.   05m00s      _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
```

### Query a specific record type

Any DNS record type can be queried, e.g. `-q NS`, `-q CAA`, `-q DNSKEY`, or `-q HTTPS`.

```sh
$ zns cloudflare.com -q HTTPS
HTTPS   cloudflare.com.   01m00s   1 . alpn="h3,h2" ipv4hint="104.16.132.229,104.16.133.229" ipv6hint="2606:4700::6810:84e5,2606:4700::6810:85e5"
```

```sh
$ zns cloudflare.com -q DNSKEY
DNSKEY   cloudflare.com.   17m28s   257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
DNSKEY   cloudflare.com.   17m28s   256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
```

```sh
$ zns cloudflare.com -q CAA
CAA   cloudflare.com.   04m20s   0 issuewild ssl.com
CAA   cloudflare.com.   04m20s   0 issuewild digicert.com; cansignhttpexchanges=yes
CAA   cloudflare.com.   04m20s   0 issuewild pki.goog; cansignhttpexchanges=yes
CAA   cloudflare.com.   04m20s   0 issue ssl.com
CAA   cloudflare.com.   04m20s   0 issuewild letsencrypt.org
CAA   cloudflare.com.   04m20s   0 issuewild comodoca.com
CAA   cloudflare.com.   04m20s   0 issue comodoca.com
CAA   cloudflare.com.   04m20s   0 issue letsencrypt.org
CAA   cloudflare.com.   04m20s   0 iodef mailto:tls-abuse@cloudflare.com
CAA   cloudflare.com.   04m20s   0 issue pki.goog; cansignhttpexchanges=yes
CAA   cloudflare.com.   04m20s   0 issue digicert.com; cansignhttpexchanges=yes
```

### Query multiple record types

Types can be passed as bare arguments (`zns cloudflare.com CAA HTTPS`), comma-separated (`-q CAA,HTTPS`), or by repeating the flag (`-q CAA -q HTTPS`). Results render in the requested order.

```sh
$ zns cloudflare.com -q CAA HTTPS
CAA     cloudflare.com.   02m27s   0 issuewild ssl.com
CAA     cloudflare.com.   02m27s   0 issuewild digicert.com; cansignhttpexchanges=yes
CAA     cloudflare.com.   02m27s   0 issuewild pki.goog; cansignhttpexchanges=yes
CAA     cloudflare.com.   02m27s   0 issue ssl.com
CAA     cloudflare.com.   02m27s   0 issuewild letsencrypt.org
CAA     cloudflare.com.   02m27s   0 issuewild comodoca.com
CAA     cloudflare.com.   02m27s   0 issue comodoca.com
CAA     cloudflare.com.   02m27s   0 issue letsencrypt.org
CAA     cloudflare.com.   02m27s   0 iodef mailto:tls-abuse@cloudflare.com
CAA     cloudflare.com.   02m27s   0 issue pki.goog; cansignhttpexchanges=yes
CAA     cloudflare.com.   02m27s   0 issue digicert.com; cansignhttpexchanges=yes
HTTPS   cloudflare.com.   05m00s   1 . alpn="h3,h2" ipv4hint="104.16.132.229,104.16.133.229" ipv6hint="2606:4700::6810:84e5,2606:4700::6810:85e5"
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
  "domain": "example.com",
  "level": "info",
  "message": "Successful query",
  "record": "93.184.215.14",
  "timestamp": "2024-12-17T01:04:06.104173+01:00",
  "ttl": "33m10s",
  "type": "A",
  "version": "dev",
  "view": "json"
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

