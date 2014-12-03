/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/rpl/rpl.h"

#include "dev/serial-line.h"
#include <stdio.h>

#include <string.h>

#include "config.h"
#define DEBUG 1
#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"

#include "debug.h"
#include "dtls.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define MAX_PAYLOAD_LEN 120

static struct uip_udp_conn *client_conn;
static dtls_context_t *dtls_context;
static char client_buf[200];
static size_t buflen = 0;
#if REBOOT_AFTER_HANDSHAKE
static uint8 data_exchanged = 0;
#endif /* REBOOT_AFTER_HANDSHAKE */

#if ONLY_RESUMPTION
unsigned char my_ticket_secret[] = {
    //0x2b, 0x1e, 0x88, 0x22, 0x21, 0x54, 0x46, 0x10, 0x07, 0x72, 0x34, 0xdf, 0x5d, 0x11, 0xd2, 0xea
    0x5b, 0x37, 0xf8, 0x7b, 0xd1, 0x88, 0x36, 0x1f, 0x37, 0xee, 0xa4, 0x5f, 0x0d, 0xe1, 0xc2, 0xf8
};
unsigned char my_ticket_secret_id[] = {
    //0xa3, 0x27, 0xa0, 0xba, 0x59, 0x66, 0x1e, 0xe2
    0xd3, 0x36, 0x10, 0xd2, 0x09, 0x81, 0x0e, 0xdf
};
#endif /* ONLY_RESUMPTION */


#if WITH_PKI
const unsigned char Client_Certificate[] = {
    0x4d, 0x49, 0x49, 0x42,
    0x44, 0x6a, 0x43, 0x42, 0x74, 0x51, 0x49, 0x4a, 0x41, 0x49, 0x2b, 0x5a, 0x6f, 0x6f, 0x33, 0x78,
    0x41, 0x41, 0x52, 0x68, 0x4d, 0x41, 0x6b, 0x47, 0x42, 0x79, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39,
    0x42, 0x41, 0x45, 0x77, 0x44, 0x7a, 0x45, 0x4e, 0x4d, 0x41, 0x73, 0x47, 0x41, 0x31, 0x55, 0x45,
    0x41, 0x77, 0x77, 0x45, 0x55, 0x30, 0x6c, 0x44, 0x55, 0x7a, 0x41, 0x65, 0x0a, 0x46, 0x77, 0x30,
    0x78, 0x4d, 0x7a, 0x41, 0x78, 0x4d, 0x54, 0x45, 0x78, 0x4e, 0x6a, 0x45, 0x79, 0x4d, 0x54, 0x4a,
    0x61, 0x46, 0x77, 0x30, 0x79, 0x4d, 0x7a, 0x41, 0x78, 0x4d, 0x44, 0x6b, 0x78, 0x4e, 0x6a, 0x45,
    0x79, 0x4d, 0x54, 0x4a, 0x61, 0x4d, 0x42, 0x45, 0x78, 0x44, 0x7a, 0x41, 0x4e, 0x42, 0x67, 0x4e,
    0x56, 0x42, 0x41, 0x4d, 0x4d, 0x42, 0x6b, 0x4e, 0x73, 0x61, 0x57, 0x56, 0x75, 0x0a, 0x64, 0x44,
    0x42, 0x5a, 0x4d, 0x42, 0x4d, 0x47, 0x42, 0x79, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x41, 0x67,
    0x45, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x41, 0x77, 0x45, 0x48, 0x41, 0x30,
    0x49, 0x41, 0x42, 0x47, 0x4f, 0x4c, 0x65, 0x6f, 0x32, 0x77, 0x6d, 0x51, 0x5a, 0x37, 0x36, 0x58,
    0x6e, 0x39, 0x73, 0x6a, 0x37, 0x2f, 0x63, 0x62, 0x31, 0x51, 0x42, 0x31, 0x51, 0x44, 0x0a, 0x6a,
    0x67, 0x64, 0x35, 0x4e, 0x33, 0x57, 0x4f, 0x37, 0x42, 0x7a, 0x58, 0x33, 0x2f, 0x4d, 0x36, 0x5a,
    0x2f, 0x54, 0x4a, 0x76, 0x36, 0x55, 0x30, 0x6d, 0x6a, 0x63, 0x46, 0x36, 0x50, 0x69, 0x67, 0x6b,
    0x50, 0x35, 0x74, 0x65, 0x64, 0x31, 0x59, 0x52, 0x50, 0x77, 0x6e, 0x63, 0x6d, 0x44, 0x30, 0x71,
    0x4b, 0x66, 0x51, 0x53, 0x54, 0x43, 0x54, 0x63, 0x2f, 0x6f, 0x77, 0x43, 0x51, 0x59, 0x48, 0x0a,
    0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x45, 0x41, 0x51, 0x4e, 0x4a, 0x41, 0x44, 0x42, 0x47,
    0x41, 0x69, 0x45, 0x41, 0x77, 0x36, 0x38, 0x36, 0x77, 0x75, 0x68, 0x39, 0x30, 0x37, 0x53, 0x38,
    0x44, 0x70, 0x36, 0x4c, 0x55, 0x68, 0x6b, 0x39, 0x4d, 0x44, 0x79, 0x2f, 0x31, 0x75, 0x31, 0x46,
    0x52, 0x41, 0x58, 0x4c, 0x75, 0x6d, 0x50, 0x64, 0x66, 0x55, 0x70, 0x7a, 0x67, 0x7a, 0x59, 0x43,
    0x0a, 0x49, 0x51, 0x44, 0x35, 0x41, 0x37, 0x39, 0x2f, 0x53, 0x63, 0x50, 0x64, 0x2f, 0x48, 0x6b,
    0x75, 0x37, 0x33, 0x53, 0x34, 0x46, 0x6d, 0x43, 0x55, 0x5a, 0x72, 0x6d, 0x4f, 0x57, 0x63, 0x55,
    0x53, 0x6e, 0x39, 0x33, 0x6e, 0x6f, 0x53, 0x6b, 0x53, 0x55, 0x68, 0x53, 0x48, 0x57, 0x67, 0x3d,
    0x3d, 0x0a,
};
#endif /* WITH_PKI */

void
try_send(struct dtls_context_t *ctx, session_t *dst) {
  int res;
  res = dtls_write(ctx, dst, (uint8 *)client_buf, buflen);
  if (res > 0) {
    memmove(client_buf, client_buf + res, buflen - res);
    buflen -= res;
    PRINTF("Client sent %d bytes \n", res);

#if REBOOT_AFTER_HANDSHAKE
    data_exchanged++;
    if (data_exchanged >= 1) {
      printf("Reboot!\n");
      SYS_REBOOT;
    }
#endif /* REBOOT_AFTER_HANDSHAKE */

  }
}

int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    PRINTF("%c", data[i]);
  return 0;
}

int
simple_send_to_peer(session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn conn;

  uip_ipaddr_copy(&conn.ripaddr, &session->addr);
  conn.rport = session->port;

  PRINTF("udp-send to ");
  PRINT6ADDR(&conn.ripaddr);
  PRINTF(" %d \n", len);
  uip_udp_packet_send(&conn, data, len);

  return len;
}

int
send_to_peer(struct dtls_context_t *ctx, 
       session_t *session, uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(" %d \n", len);

  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  /* FIXME: do we want this at all? */
  memset(&conn->ripaddr, 0, sizeof(client_conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

int
get_key(struct dtls_context_t *ctx, 
	const session_t *session, 
	const unsigned char *id, size_t id_len, 
	const dtls_key_t **result) {

#if WITH_PKI
  static const dtls_key_t pki = {
    .type = DTLS_KEY_PKI,
    /* public key identity (root CA) */
    .key.pki.id_pubkey = (unsigned char *) "SICS",
    /* public key identity length */
    .key.pki.id_pubkey_length = 4,
    /* public key key data */
    .key.pki.pubkey = (unsigned char *)
        "9BC63C75FC8235A39224132B99769961"
        "B0D3A8C477A2CC2581B5A260F636156B"
        "22E265E8B5B63653F1464C75A7874493"
        "3F84B60A4FBC96A53BFA291FE3D7C049",
    /* public key key data length */
    .key.pki.pubkey_length = 64,
    /* my private key */
    .key.pki.private_key = (unsigned char *)
        "3469B095F7D997DA9CE994E9CE8882FF"
        "4A076F40FD3E921A43FA18D453934495",
    /* length of my private key */
    .key.pki.private_key_length = 32,
    .key.pki.certificate_id = (unsigned char *) "Client",
    .key.pki.certificate_id_length = 6,
    /* my Certificate (does not contain comments) */
    .key.pki.certificate = Client_Certificate,
    /* length of my Certificate */
    .key.pki.certificate_length = sizeof(Client_Certificate)
  };
  *result = &pki;
#elif ONLY_RESUMPTION
  static const dtls_key_t abbr = {
      .type = DTLS_KEY_ABBR,
      /* peer's SessionTicket */
      .key.abbr.session_ticket = NULL,
      .key.abbr.session_ticket_len= 0,
      /* storing my own ticket */
      .key.abbr.my_session_ticket = NULL,
      /* the secret to encrypt my SessionTicket */
      .key.abbr.ticket_secret = my_ticket_secret,
      /* the name of the secret key */
      .key.abbr.ticket_secret_id = my_ticket_secret_id,
      .key.abbr.id_pubkey = (unsigned char *) "SICS",
      .key.abbr.id_pubkey_length = 4,
      .key.abbr.certificate_id = (unsigned char *) "Client",
      .key.abbr.certificate_id_length = 6
  };
  *result = &abbr;
#else /* WITH_PKI */
  static const dtls_key_t psk = {
    .type = DTLS_KEY_PSK,
    .key.psk.id = (unsigned char *)"Client_identity", 
    .key.psk.id_length = 15,
    .key.psk.key = (unsigned char *)"secretPSK", 
    .key.psk.key_length = 9
  };
  *result = &psk;
#endif /* WITH_PKI */

  return 0;
}

PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
dtls_handle_read(dtls_context_t *ctx) {
  static session_t session;

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    ((char *)uip_appdata)[uip_datalen()] = 0;
    PRINTF("Client received %u Byte message from ", uip_datalen());
    PRINT6ADDR(&session.addr);
    PRINTF(":%d\n", uip_ntohs(session.port));

    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}

static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
#define _QUOTEME(x) #x
#define QUOTEME(x) _QUOTEME(x)
#ifdef UDP_CONNECTION_ADDR
  if(uiplib_ipaddrconv(QUOTEME(UDP_CONNECTION_ADDR), ipaddr) == 0) {
    PRINTF("UDP client failed to parse address '%s'\n", QUOTEME(UDP_CONNECTION_ADDR));
  }
#elif UIP_CONF_ROUTER
#if defined(TMOTE_SKY)
  //uip_ip6addr(ipaddr,0xfe80,0,0,0,0x0212,0x7401,0x0001,0x0101);
  uip_ip6addr(ipaddr,0xfe80,0,0,0,0,0,0,0x0001);
#else /* TMOTE_SKY*/

  // Hardware
  //uip_ip6addr(ipaddr,0xfe80,0,0,0,0x0200,0,0,0x0003);
  // COOJA
  uip_ip6addr(ipaddr,0xfe80,0,0,0,0x0200,0,0,0x0001);
  //uip_ip6addr(ipaddr,0xfdfd,0,0,0,0,0,0,0x0001);
  //uip_ip6addr(ipaddr,0xbbbb,0,0,0,0,0xff,0xfe00,0x0010);
#endif /* TMOTE_SKY*/
#else

#if defined(CONTIKI_TARGET_MINIMAL_NET)
    //localhost fe80::1
    uip_ip6addr(ipaddr,0xfe80,0,0,0,0,0,0,0x0001);
#else
  uip_ip6addr(ipaddr,0xfe80,0,0,0,0x6466,0x6666,0x6666,0x6666);
#endif /* CONTIKI_TARGET_MINIMAL_NET */

#endif /* UDP_CONNECTION_ADDR */

}

void
init_dtls(session_t *dst) {
  static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_peer,
    .event = NULL,
    .get_key = get_key
  };
  PRINTF("DTLS client started\n");

  print_local_addresses();

  dst->size = sizeof(dst->addr) + sizeof(dst->port);
  dst->port = UIP_HTONS(20220);

  set_connection_address(&dst->addr);
  client_conn = udp_new(&dst->addr, 0, NULL);
  udp_bind(client_conn, dst->port);

  PRINTF("set connection address to ");
  PRINT6ADDR(&dst->addr);
  PRINTF(":%d\n", uip_ntohs(dst->port));

  set_log_level(LOG_DEBUG);

  dtls_context = dtls_new_context(client_conn);
  if (dtls_context)
    dtls_set_handler(dtls_context, &cb);
#if STATIC_ROUTING
  /* static routing */
  uip_ipaddr_t ipaddr_nxh;
  //uip_ip6addr(&ipaddr_nxh, 0xaaaa, 0, 0, 0, 0x0200, 0, 0, 3);
  uip_ip6addr(&ipaddr_nxh, 0xfe80, 0, 0, 0, 0x0200, 0, 0, 0x0003);
  uip_lladdr_t lladdr;
  memcpy(&lladdr, dst->addr.u8[8], UIP_LLADDR_LEN);
  if(uip_ds6_nbr_add(&ipaddr_nxh, &lladdr, 1, NBR_REACHABLE) == NULL){
    printf("add nbr fail\n");
  }
  /* next hope for dest*/
  uip_ds6_route_add(&dst->addr, 128, &ipaddr_nxh);
#endif /* STATIC_ROUTING */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static int connected = 0;
  static session_t dst;
  static struct etimer et;


  PROCESS_BEGIN();

  dtls_init();

  init_dtls(&dst);
  serial_line_init();

  if (!dtls_context) {
    dsrv_log(LOG_EMERG, "cannot create context\n");
    PROCESS_EXIT();
  }

#if UIP_CONF_IPV6_RPL
  /* Wait until RPL is ready */
  while (rpl_get_any_dag == NULL) {
    PROCESS_PAUSE();
  }
#endif /* UIP_CONF_IPV6_RPL */

  /* work around to force Neighbor Discovery. Otherwise first DTLS message is
   * must be re-transmitted which adds currently ~20sec to the handshake time
   */
  //uip_udp_packet_sendto(client_conn, client_buf, 1, &(dst.addr), UIP_HTONS(20220));

  clock_wait(1*CLOCK_SECOND); // give Border Router some time
  memcpy(client_buf,".", 1);
  simple_send_to_peer(&dst, client_buf, 1);
  simple_send_to_peer(&dst, client_buf, 1);
  clock_wait(1*CLOCK_SECOND); // after reset give server some time

  etimer_set(&et, CLOCK_SECOND * 2);
  while(1) {
    PROCESS_YIELD();
//    if(ev == serial_line_event_message) {
//      printf("received line: %s\n", (char *)data);
//      if (strcmp((char *)data, "reboot") == 0) {
//        printf("system reboot!\n");
//      }
//      continue;
//    }
    if(ev == tcpip_event) {
      dtls_handle_read(dtls_context);
    } else if (ev == PROCESS_EVENT_TIMER) {
      if (buflen == 16)
        continue;
      buflen = 16;
      memcpy(client_buf,"Client says Hi\n", buflen);
    }

    if (buflen) {
      if (!connected) {
        etimer_set(&et, CLOCK_SECOND * 2);
	connected = dtls_connect(dtls_context, &dst) >= 0;
      }
      
      try_send(dtls_context, &dst);
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
