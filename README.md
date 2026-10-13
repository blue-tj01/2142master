2142 Master Server
==============

Revive 2142 project for complete gamespy / fesl replacement

TODO:
---------------------
- Catch packets and reverse protocols including SSL encrypted hosts

- Basic FESL EA backend emulation (fesl.ea.com) for BF2142

- Support for GameSpy protocols and subaccounts

- Support for various databases (MySQL, PostgreSQL, SQlite3)

- Daemonization for each service

- Ini configuration support



Building the capture proxy
---------------------

`src/` contains Luigi Auriemma's stcppipe, used to capture (including SSL) traffic between the game and its servers. BF2142's FESL login uses SSLv3, which current Linux OpenSSL packages no longer support. `make ssl3` downloads OpenSSL 1.1.1w, builds it with SSLv3 and weak ciphers (RC4) enabled, and links stcppipe statically against it:

    cd src && make ssl3
    ./stcppipe -S -X ssl3 "" "" -d dumps <fesl_host> <port> <port>

This OpenSSL build is insecure on purpose: only use it for this capture proxy. `make` alone builds against the system OpenSSL (1.0.x or 1.1+/3.x) without SSLv3.

Windows binaries are available from the author's site: http://aluigi.altervista.org/mytoolz.htm


If you wish to modify the code and add support for your game, or add any additional features, please feel free to make a **fork** and submit a [pull request].


Credits
---------------------

[Artyom Shcherbakov aka Tema567] (http://art567.ru).

[Luigi Auriemma aka aluigi] e-mail: aluigi@autistici.org