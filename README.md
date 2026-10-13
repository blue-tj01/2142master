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

`src/` contains Luigi Auriemma's stcppipe, used to capture (including SSL) traffic between the game and its servers. On Linux it builds against OpenSSL 1.0.x or 1.1+/3.x:

    cd src && make

Windows binaries are available from the author's site: http://aluigi.altervista.org/mytoolz.htm


If you wish to modify the code and add support for your game, or add any additional features, please feel free to make a **fork** and submit a [pull request].


Credits
---------------------

[Artyom Shcherbakov aka Tema567] (http://art567.ru).

[Luigi Auriemma aka aluigi] e-mail: aluigi@autistici.org