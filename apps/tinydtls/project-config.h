#ifndef _PROJECT_CONFIG_H_
#define _PROJECT_CONFIG_H_

/* ALL THE DEFINES THAT OVERWRITE THE DEFINES IN PLATFORM SPECIFIC CONTIKI-CONF.H */

/* No DEBUG: This turns off Debug output */
#define NDEBUG

/* Reducing RAM and ROM usage in Contiki
 * Processes headers contain pointers to ASCII strings that are used only for
 * informational printing.
 * Default is not enabled */
#undef  PROCESS_CONF_NO_PROCESS_NAMES
#define PROCESS_CONF_NO_PROCESS_NAMES   1

/* Enable in node evaluation*/
#define EVAL_SYMMETRIC_CRYPTO           0
#define EVAL_IN_NODE_PROCESSING         0
#define EVAL_HANDSHAKE_RUN_TIME         1
#define REBOOT_AFTER_HANDSHAKE          1
#define REBOOT_AFTER_HANDSHAKE_FINISH   0
#define STACK_DUMP                      0

/* RElIC is very slow without assembly support. This support can't be used with
 * 20 bit address support We measure the required time with assembly support
 * and do busy wait instead of Crypto operations. */
#define BUSY_WAIT_DSA                   1
#define BUSY_WAIT_DH                    1

/* static routing, define in client and server */
#define STATIC_ROUTING                  1


#if STACK_DUMP
#define STACK_DUMP_SIZE 1120
#define STACK_MAGIC 0x27
#endif

/* Use the AES Hardware support provided by CC2520 */
#ifndef AES_HARDWARE_CC2520
#define AES_HARDWARE_CC2520            0
#endif /* AES_HARDWARE */

/* Define Crypto Backend: Defualt DEX-CCM */
#ifndef DEX_CCM
#define DEX_CCM                         1
#endif /* DEX_CCM */


/* Disabling TCP which eliminates a MSS-sized buffer */
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
#define UIP_CONF_DS6_NBR_NBU            2
#undef  UIP_CONF_DS6_ROUTE_NBU
#define UIP_CONF_DS6_ROUTE_NBU          2

/* Turning RPL on/off IMPORTANT: Modify as well the Makefile for RPL */
#undef  UIP_CONF_IPV6_RPL
#define UIP_CONF_IPV6_RPL               0
/* IMPORTNAT: #define UIP_CONF_RPL      0
 * Setting the RPL in this file has no effect. It should be set
 * in the Makefile */

/* Fragmentation support is enabled */
#define SICSLOWPAN_CONF_FRAG            1

/* Increasing the UIP buffer size */
#undef UIP_CONF_BUFFER_SIZE
#if ABBREVIATION
#define UIP_CONF_BUFFER_SIZE            250
#else /* ABBREVIATION */
#define UIP_CONF_BUFFER_SIZE            450
#endif /* ABBREVIATION */

//#undef HARD_CODED_ADDRESS
//#define HARD_CODED_ADDRESS      "fdfd::10"

#endif /* _PROJECT_CONFIG_H_ */
