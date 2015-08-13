all: paillier-test

APPS += flash-erase relic blowfish
CONTIKI = ../../..

CFLAGS += -DPROJECT_CONF_H=\"project-config.h\"
CFLAGS += -DUIP_CONF_IPV6=0 -DUIP_CONF_TCP=0

WITH_UIP6=0
UIP_CONF_RPL=0

# Crypto Library
RELIC_TARGET=${CONTIKI}/../relic/build
PROJECT_LIBRARIES += ${RELIC_TARGET}/lib/librelic_s.a


CFLAGS+= -ffunction-sections


include $(CONTIKI)/Makefile.include
