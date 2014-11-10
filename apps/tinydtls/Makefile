all: dtls-server dtls-client
	$(MAKE) $(MAKEFLAGS) ROLE=server dtls-server
	$(MAKE) $(MAKEFLAGS) clean
	$(MAKE) $(MAKEFLAGS) ROLE=client dtls-client

CONTIKI=../..
CFLAGS += -DPROJECT_CONF_H=\"project-config.h\"

WITH_UIP6=1
UIP_CONF_IPV6=1
UIP_CONF_RPL=0
#RPL_LEAF_ONLY=1

# new variable since slip-radio
ifeq ($(TARGET), minimal-net)
# minimal-net does not support RPL under Linux and is mostly used to test CoAP only
${info INFO: compiling for minimal-net}
CFLAGS += -DUIP_CONF_ND6_DEF_MAXDADNS=0
CFLAGS += -DHARD_CODED_ADDRESS=\"bbbb::10\"
endif

ABBREVIATION=1

ifneq ($(ROLE),client)
    CFLAGS+=-DNODE_ID=2
    CFLAGS+=-DNET_PREFIX=0xbbbb
	#CFLAGS+= -DHARD_CODED_ADDRESS=\"bbbb::200:0:0:2\"
${info INFO: server}
else
	CFLAGS+=-DNODE_ID=1
	CFLAGS+=-DNET_PREFIX=0xaaaa
	#NET_PREFIX=0xaaaa
${info INFO: client}
	#CFLAGS+= -DUDP_CONNECTION_ADDR="fe80::ff:fe02:232" \
		 -DHARD_CODED_ADDRESS=\"aaaa::02:230\"
endif

ifeq ($(ABBREVIATION), 0)
ifeq ($(TARGET), minimal-net)
# check if relic library is present
$(if $(wildcard relic_minimal-net/librelic_s.a),,$(error "relic library is missing."))
$(if $(wildcard relic_minimal-net/include/relic.h),,$(error "relic library is missing."))
# support for relic-toolkit library
PROJECT_LIBRARIES+= relic_minimal-net/librelic_s.a
else # TARGET
# check if relic library is present
$(if $(wildcard relic/librelic_s.a),,$(error "relic library is missing."))
$(if $(wildcard relic/include/relic.h),,$(error "relic library is missing."))
# support for relic-toolkit library
PROJECT_LIBRARIES+= relic/librelic_s.a
endif # TARGET
endif # ABBREVIATOION


CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DUIP_CONF_TCP=0 -DSHA2_USE_INTTYPES_H
# TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 and not PSK


ifeq ($(ABBREVIATION), 1)
${info INFO: compiling with abbreviated handshake}
CFLAGS += -DWITH_PKI=0
#CFLAGS += -DONLY_RESUMPTION=1
#CFLAGS += -DWITH_RESUMPTION=1
else
#${info INFO: compiling with exptended PKI}
${info INFO: compiling with standard PKI}
CFLAGS += -DWITH_PKI=1
CFLAGS += -DONLY_RESUMPTION=0
CFLAGS += -DWITH_RESUMPTION=0
PROJECT_SOURCEFILES += cert-parser.c
endif


# Define Crypto
DEX_CCM=1
CFLAGS+= -DDEX_CCM=1

ifeq ($(DEX_CCM), 1)
${info INFO: compiling DEX_CCM}
AES_HARDWARE_CC2520=0
CFLAGS+= -DAES_HARDWARE_CC2520=0
APPS += tinydtls/dex-ccm tinydtls/sha2 tinydtls
else
${info INFO: compiling Rijndael}
APPS += tinydtls/aes tinydtls/sha2 tinydtls
endif


include $(CONTIKI)/Makefile.include