#ifndef _PROJECT_CONFIG_H_
#define _PROJECT_CONFIG_H_

/* ALL THE DEFINES THAT OVERWRITE THE DEFINES IN PLATFORM SPECIFIC CONTIKI-CONF.H */

/* Reducing RAM and ROM usage in Contiki
 * Processes headers contain pointers to ASCII strings that are used only for
 * informational printing.
 * Default is not enabled */
#undef  PROCESS_CONF_NO_PROCESS_NAMES
#define PROCESS_CONF_NO_PROCESS_NAMES   1

/* Disabling TCP which eliminates a MSS-sized buffer */
#undef UIP_CONF_TCP
#define UIP_CONF_TCP                    0

/* Use nullrdc_driver instead of contikimac_driver to save memory */
#undef  NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC               nullrdc_driver
/* #define NETSTACK_CONF_RDC               contikimac_driver */

/* nullmac_driver takes less space than csma_driver */
#undef  NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC     nullmac_driver
/* #define NETSTACK_CONF_MAC     csma_driver */

/* Specify whether the RDC layer should enable
 * per-packet power profiling.
 * Default is enabled */
#undef  CONTIKIMAC_CONF_COMPOWER
#define CONTIKIMAC_CONF_COMPOWER        0
#undef  XMAC_CONF_COMPOWER
#define XMAC_CONF_COMPOWER              0
#undef  CXMAC_CONF_COMPOWER
#define CXMAC_CONF_COMPOWER             0

/* energy estimation is per Default enabled*/
#undef ENERGEST_CONF_ON
#define ENERGEST_CONF_ON                0

/* this triggers the use to TI AES instead of hardware AES
 * NOTE: comment out for real nodes */
//#define CONTIKI_AES_SOFTWARE

/* configure number of neighbors and routes
 * NOTE: this considerably decreases ROM requirements of Contiki
 * Default number is 20 for sky and 30 for wismote platform */
#undef  UIP_CONF_DS6_NBR_NBU
#define UIP_CONF_DS6_NBR_NBU            1
#undef  UIP_CONF_DS6_ROUTE_NBU
#define UIP_CONF_DS6_ROUTE_NBU          1

/* Turning RPL on/off IMPORTANT: Modify as well the Makefile for RPL */
#undef  UIP_CONF_IPV6_RPL
#define UIP_CONF_IPV6_RPL               0
/* IMPORTNAT: #define UIP_CONF_RPL      0
 * Setting the RPL in this file has no effect. It should be set
 * in the Makefile */

/* Reduce 802.15.4 frame queue to save RAM. */
#undef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM               1

#undef SICSLOWPAN_CONF_FRAG
#define SICSLOWPAN_CONF_FRAG  0

/* A MAC protocol that does nothing (saving 1044 Byte)*/
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER  framer_nullmac


#endif /* _PROJECT_CONFIG_H_ */
