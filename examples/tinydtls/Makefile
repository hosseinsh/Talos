all: dtls-client dtls-server

CONTIKI = ../..

HAVE_BANKING=1
UIP_CONF_RPL=1
UIP_CONF_IPV6=1

DEFINES+=PROJECT_CONF_H=\"project-conf.h\" WITH_UIP6=1

APPS += tinydtls

include $(CONTIKI)/Makefile.include
