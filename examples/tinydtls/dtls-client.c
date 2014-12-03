/*
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <project-conf.h>

//Contiki OS Includes
#include <contiki.h>
#include <contiki-lib.h>
#include <contiki-net.h>
#include <list.h>
#include <mt.h>
#include <log.h>

//System Includes
#include <string.h>

//Additional Apps and Drivers
#include <dtls-client.h>
#include <leds.h>
#include <dtls.h>
#include <debug.h>
#include <serial-line.h>

/*
 * Input Buffer
 */
struct dtls_message_list_element {
  struct dtls_message_list_element* next;
  session_t session;
  uint8_t*  msg;
  int       msg_len;
};
LIST(dtls_message_list);

/*
 * Private Members
 */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])
static struct uip_udp_conn *server_conn;
static dtls_context_t *dtls_context = NULL;
static session_t client_session;

/*
 * Define Process
 */
PROCESS(dtls_client_process, "DTLS client process");
AUTOSTART_PROCESSES(&dtls_client_process);

/*
 * Called by DTLS to pass us a decoded incoming message
 */
static int read_from_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
  /*
   * Output incoming Message
   */
  size_t i; for (i = 0; i < len; i++) {
    printf("%c", data[i]);
  }

  return 0;
}

/*
 * Called by DTLS to transmit an encoded outgoing message
 */
static int send_to_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
  /*
   * Restore destination Address
   */
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

  /*
   * Transmit message
   */
  printf(YELLOW "Sending Message: %u\n" DEFAULT, len);
  uip_udp_packet_send(conn, data, len);

  /*
   * Clear destination Address to allow data from any node
   */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  /*
   * Release CPU for a short while
   */
  process_post(PROCESS_CURRENT(), PROCESS_EVENT_CONTINUE, NULL);
  mt_yield();
 
  return len;
}

/**
 * Called during handshake to get the server's or client's ecdsa
 * key used to authenticate this server or client in this
 * session.
 */
static int get_ecdsa_key(struct dtls_context_t *ctx,
		       const session_t *session,
		       const dtls_ecdsa_key_t **result) {

  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key  = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y,
    .cert      = client_cert,
    .cert_len  = sizeof(client_cert)
  };
  *result = &ecdsa_key;

  return 0;
}

/**
 * Called during handshake to check the peer's pubic key in this
 * session. If the public key matches the session and should be
 * considerated valid the return value must be @c 0. If not valid,
 * the return value must be less than zero.
 */
int verify_ecdsa_key(struct dtls_context_t *ctx,
			  const session_t *session,
			  const unsigned char *other_pub_x,
			  const unsigned char *other_pub_y,
			  size_t key_size) {

	return 0;
}

/**
 * Called during handshake to check the peer's certificate and
 * extract the public key. If the public key matches the session
 * and should be considerate valid the return value must be @c 0.
 * If not valid, the return value must be less than zero.
 *
 * Additionally the public key has to be written to the two buffers
 * other_pub_x other_pub_y.
 */
int verify_ecdsa_cert(struct dtls_context_t *ctx,
      const session_t *session,
      const unsigned char *cert, size_t cert_len,
      unsigned char *other_pub_x,
      unsigned char *other_pub_y,
      size_t key_size) {

  printf(CYAN "ASN.1 Parser is missing, Peer's Public Key is hard coded\n" DEFAULT);
  memcpy(other_pub_x, ecdsa_pub_key_x, 32);
  memcpy(other_pub_y, ecdsa_pub_key_y, 32);

  return 0;
}

/*
 * This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given Identity within this particular
 * session.
 */
int get_psk_info(struct dtls_context_t *ctx,
             const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *desc, size_t desc_len,
             unsigned char *result, size_t result_length) {

  switch(type) {
    case DTLS_PSK_HINT:
      sprintf((char*)result, "Client_identity");
      return 15;
    case DTLS_PSK_KEY:
      sprintf((char*)result, "secretPSK");
      return 9;
    case DTLS_PSK_IDENTITY:
      return 0;
    default:
      printf(RED "get_psk_info(): unknown type\n" DEFAULT);
      return -1;
  }
}

/*
 * Callbacks used in conjunction with DTLS
 */
static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
  .get_psk_info = get_psk_info,
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key,
  .verify_ecdsa_cert = verify_ecdsa_cert
};

/*
 * Handle incoming packet
 */
static void dtls_handle_read() {
  if(uip_datalen()) {
    /*
     * Allocate Memory
     */
    struct dtls_message_list_element *element = malloc(sizeof(struct dtls_message_list_element));
    element->msg = malloc(uip_datalen());
    
    /*
     * Read Data
     */
    dtls_session_init(&element->session);
    uip_ipaddr_copy(&element->session.addr, &UIP_IP_BUF->srcipaddr);
    element->session.port = UIP_UDP_BUF->srcport;
    element->msg_len = uip_datalen();
    memcpy(element->msg, uip_appdata, uip_datalen());
    printf(GREEN "Received Message: %u\n" DEFAULT, uip_datalen());

    /*
     * Add to List
     */
    list_add(dtls_message_list, element);
  }
}

/*
 * The TinyDTLS runs on a separate stack to allow preemption
 * while long lasting calculation are running on the PKA
 */
static void thread_main(void *dtls_context) {
  /*
   * Get oldest message
   */
  struct dtls_message_list_element *element;
  element = list_pop(dtls_message_list);

  if(element != NULL) {
    /*
     * Pass incoming packet to DTLS library
     */
    printf(GREEN "Processing Message: %u\n" DEFAULT, element->msg_len);
    dtls_handle_message(dtls_context, &element->session, element->msg, element->msg_len);

    /*
     * Release Memory
     */
    free(element->msg);
    free(element);

    /*
     * Notify main loop
     */
    process_post(PROCESS_CURRENT(), PROCESS_EVENT_CONTINUE, NULL);
  }
}

/**
 * The DTLS Client initialized DTLSv2 Secured UDP Connections
 * every 10s and sends a ping.
 */
PROCESS_THREAD(dtls_client_process, ev, data) {
  PROCESS_BEGIN();
  /*
   * Setup Environment for Multithreading
   */
  mt_init();
  static struct mt_thread dtls_thread;
  dtls_thread.state = 5;
  
  /*
   * Open UDP Connection
   */
  list_init(dtls_message_list);
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(DTLS_ECHO_PORT));
  printf("Enter Server Address (w/o abbreviation e.g. aaaa:0000:0000:0000:0212:4b00:03a5:707e)\n");
  printf("=> ");
  
  /*
   * Configure DTLS on top of server_conn
   */
  dtls_init();
  dtls_set_log_level(DTLS_LOG_INFO);
  dtls_context = dtls_new_context(server_conn);
  dtls_set_handler(dtls_context, &cb);

  if(!dtls_context) {
    printf("Cannot create context.\n");
    PROCESS_EXIT();
  }

  /*
   * Process Events
   */
  while(1) {
    /*
     * Wait for internal or external events
     */
    PROCESS_WAIT_EVENT();

    /*
     * Process event from Test-Interface
     */
    if(ev == serial_line_event_message && data != NULL) {
      dtls_session_init(&client_session);
      static unsigned int addr[8];
	  printf("%s\n", (char*)data);
      if(sscanf((char*)data, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                             &addr[0],&addr[1],&addr[2],&addr[3],
                             &addr[4],&addr[5],&addr[6],&addr[7]) == 8) {

        uip_ip6addr(&client_session.addr, addr[0], addr[1], addr[2], addr[3],
                                          addr[4], addr[5], addr[6], addr[7]);
        client_session.port = UIP_HTONS(20220);
        dtls_connect(dtls_context, &client_session);
      } else {
        printf("IPv6 address has unexpected format\n");
      }
    }

    /* 
     * If the connection is up send a message and call DTLS close
     */
    dtls_peer_t *peer;
    peer = dtls_get_peer(dtls_context, &client_session);
    if(peer && peer->state == DTLS_STATE_CONNECTED) {
      dtls_write(dtls_context, &client_session, (uint8_t*)"PING\n", 5);
      dtls_close(dtls_context, &client_session);
    }

    /*
     * If we got a new DTLS message put it into our list
     */
    if(uip_newdata()) {
      dtls_handle_read();
    }

    /*
     * If last message is done and queue is not empty begin next
     */
    if(dtls_thread.state == 5 && list_head(dtls_message_list)) {
      mt_start(&dtls_thread, thread_main, dtls_context);
    }

    /*
     * If a message is loaded (continue to) process it
     */
    if(dtls_thread.state != 5) {
      leds_on(LEDS_RED);
      mt_exec(&dtls_thread);
      leds_off(LEDS_RED);
    }
  }

  PROCESS_END();
}
