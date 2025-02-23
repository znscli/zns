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

![zns example.com](./assets/basic.png)

### Query a specific record type

![zns example.com -q NS](./assets/basic-q.png)

### Use a specific DNS server

![zns example.com -q NS --server 1.1.1.1](./assets/basic-q-s.png)

### JSON output

![zns example.com --json -q A | jq](./assets/basic-json.png)

### Writing to a file

![zns example.com that writes to a log file](./assets/basic-log-file.png)

## Contributing

Contributions are highly appreciated and always welcome.
Have a look through existing [Issues](https://github.com/znscli/zns/issues) and [Pull Requests](https://github.com/znscli/zns/pulls) that you could help with.

## License

This project is licensed under the MIT License. You are free to use, modify, and distribute the software, provided that you include the original license in any copies of the software. See the [LICENSE](LICENSE) file for more details.

