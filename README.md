# 2142 Master Server

[![test](https://github.com/blue-tj01/2142master/actions/workflows/test.yml/badge.svg)](https://github.com/blue-tj01/2142master/actions/workflows/test.yml)
[![License: GPL v2](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

This project aims to bring **Battlefield 2142** online play back by replacing the backend services EA shut down: the FESL login service (`fesl.ea.com`) and the GameSpy services.

> **Status: early development.** The protocols are being reverse engineered from captured traffic. There is a tested FESL packet decoder, but no server yet.

## Contents

- [Roadmap](#roadmap)
- [Repository layout](#repository-layout)
- [Getting started](#getting-started)
- [Capturing game traffic](#capturing-game-traffic)
- [FESL protocol overview](#fesl-protocol-overview)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

## Roadmap

- [x] Capture game traffic, including SSL-encrypted FESL sessions
- [x] FESL packet decoder and encoder, with tests that replay the captures
- [ ] Basic FESL backend emulation for BF2142 (Hello, MemCheck, Login, entitlements, sub-accounts)
- [ ] GameSpy protocols and sub-accounts
- [ ] Database backends (MySQL, PostgreSQL, SQLite3)
- [ ] Daemonization of each service
- [ ] INI configuration (minIni is already included)

## Repository layout

| Path | Contents |
| --- | --- |
| `src/server/` | FESL packet decoder/encoder (`fesl.c`, `fesl.h`) |
| `src/` | [stcppipe](http://aluigi.altervista.org/mytoolz.htm) capture proxy by Luigi Auriemma, and the minIni INI parser |
| `tests/` | Unit tests and replay tests for the FESL decoder |
| `stuff/pcap/` | Captured login sessions (`dump1.pcap` raw, `dump2_ssl.pcap` decrypted FESL) |
| `stuff/info/` | Archived FESL protocol notes from aluigi's forum |
| `doc/` | Licenses of the bundled third-party code |

## Getting started

You need a C compiler, `make`, and `unzip`. Building stcppipe against the system OpenSSL also needs the OpenSSL headers (`libssl-dev` on Debian/Ubuntu).

Run the FESL tests:

```sh
make -C tests test               # unit tests + replay of stuff/pcap captures
make -C tests test SANITIZE=1    # the same with AddressSanitizer/UBSan
```

CI runs both of these, plus the stcppipe build, on every pull request and on every push to `master`.

## Capturing game traffic

BF2142's FESL login uses **SSLv3**, which current OpenSSL packages no longer support. `make ssl3` builds stcppipe with a private OpenSSL 1.1.1w that has SSLv3 and RC4 enabled:

```sh
cd src
make ssl3     # downloads and checks OpenSSL 1.1.1w, then builds stcppipe statically against it
./stcppipe -S -X ssl3 "" "" -d dumps <fesl_host> 18300 18300
```

Point the FESL host name at the machine running stcppipe (for example through the hosts file). The decrypted traffic is written to `dumps/` in pcap format and can be opened in Wireshark.

> [!WARNING]
> The private OpenSSL build is insecure on purpose. Use it only for this capture proxy.

`make` on its own builds stcppipe against the system OpenSSL (1.0.x, or 1.1 and later), without SSLv3. Windows binaries are available from the [author's site](http://aluigi.altervista.org/mytoolz.htm).

## FESL protocol overview

Every FESL packet has a 12-byte header followed by a text body:

| Bytes | Field |
| --- | --- |
| 0–3 | Command, ASCII: `fsys`, `acct`, `subs`, `dobj`, ... |
| 4–7 | Big endian: `type << 24 \| packet number`. An answer uses the number of its request |
| 8–11 | Big endian: total packet size, header included |
| 12– | `key=value\n` lines, terminated by a NUL byte. Every packet has a `TXN` key |

Packet types are `0x80` and `0xC0` for single packets, and `0xB0` and `0xF0` for the pieces of a multipart packet. A multipart packet carries its body base64-encoded in `data=` pieces, with the total size in `size=`.

A captured login runs in this order:

1. `fsys` Hello, then the server's MemCheck
2. `acct` Login
3. `subs` GetEntitlementByBundle
4. `dobj` GetObjectInventory
5. `acct` GetSubAccounts, LoginSubAccount and GetAccount
6. `acct` GameSpyPreAuth

See [`stuff/info/`](stuff/info) for the original notes.

## Contributing

Fork the repository and open a [pull request](https://github.com/blue-tj01/2142master/pulls). New captures, protocol notes and tests are as welcome as code. Please run `make -C tests test` before submitting.

## License

The project is licensed under the [GNU GPL v2](LICENSE).

Bundled third-party code keeps its own license:

| Component | License |
| --- | --- |
| stcppipe | GPL v2 or later |
| minIni | [Apache 2.0](doc/apache-2.0.txt) |

> [!NOTE]
> Apache 2.0 code can't be combined with GPL v2-only code, so this has to be resolved before minIni is linked into the server.

## Credits

- [Artyom Shcherbakov (Tema567)](http://art567.ru): project author
- [Luigi Auriemma (aluigi)](http://aluigi.altervista.org): stcppipe and the FESL protocol research
- [CompuPhase](https://www.compuphase.com/minini.htm): minIni
