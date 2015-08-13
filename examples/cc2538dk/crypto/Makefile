CONTIKI_PROJECT = ccm-test sha256-test ecc-ecdh ecc-sign ecc-verify paillier-test
CONTIKI_PROJECT+= cbc-test

all: $(CONTIKI_PROJECT)
UIP_CONF_IPV6=1

DEFINES+=PROJECT_CONF_H=\"project-conf.h\" WITH_UIP6=1

APPS += flash-erase mOPE

CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
