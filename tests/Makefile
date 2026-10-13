# FESL decoder tests, replaying the decrypted captures in stuff/pcap
#   make test               build and run
#   make test SANITIZE=1    same with AddressSanitizer/UBSan

CFLAGS		+= -O2 -g -Wall -Wextra -I../src/server
ifdef SANITIZE
CFLAGS		+= -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS		+= -fsanitize=address,undefined
endif

DATA		= data
CAPTURES	= $(DATA)/d1/dump2_ssl.pcap $(DATA)/d2/dump2_ssl.pcap

all: test_fesl

test_fesl: test_fesl.c pcap_stream.c pcap_stream.h ../src/server/fesl.c ../src/server/fesl.h
	$(CC) $(CFLAGS) test_fesl.c pcap_stream.c ../src/server/fesl.c -o $@ $(LDFLAGS)

$(DATA)/%/dump2_ssl.pcap: ../stuff/pcap/%.zip
	mkdir -p $(DATA)/$*
	unzip -o -q $< -d $(DATA)/$*
	touch $@

test: test_fesl $(CAPTURES)
	./test_fesl $(DATA)

clean:
	rm -rf test_fesl $(DATA)

.PHONY: all test clean
