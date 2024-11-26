# zns

zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value.

* Supports various DNS record types
* Colorized and tabular output for easy reading
* Concurrent queries for improved performance
* JSON output format for machine-readable results
* Option to write output to a file

## Installing

```sh
brew install znscli/tap/zns
```

## Usage

```sh
$ zns google.com
A       google.com.    04m05s       142.251.39.110
AAAA    google.com.    04m07s       2a00:1450:400e:802::200e
MX      google.com.    03m32s       10  smtp.google.com.
NS      google.com.    93h48m24s    ns2.google.com.
NS      google.com.    93h48m24s    ns3.google.com.
NS      google.com.    93h48m24s    ns4.google.com.
NS      google.com.    93h48m24s    ns1.google.com.
SOA     google.com.    55s          ns1.google.com. dns-admin.google.com.
```

### JSON output

```sh
$ zns google.com --json | jq
{
  "@domain": "google.com",
  "@level": "info",
  "@record": "142.250.179.206",
  "@timestamp": "2024-11-26T12:48:01.400203+01:00",
  "@ttl": "04m02s",
  "@type": "A",
  "@version": "dev",
  "@view": "json"
}
{
  "@domain": "google.com",
  "@level": "info",
  "@record": "ns2.google.com.",
  "@timestamp": "2024-11-26T12:48:01.401724+01:00",
  "@ttl": "93h46m51s",
  "@type": "NS",
  "@version": "dev",
  "@view": "json"
}
...
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

