#include <stdio.h>
#include "ep.h"
#include "relay.h"
#include "nghttp2.h"

static struct ep_base* s_base = NULL;

static int relay_sys_init(struct ep_base* base) {
  s_base = base;
  return 0;
}

static void* relay_create(const char* host, int port, relay_eventcb cb, void* args) {
  return NULL;
}

static void relay_send_request(void* relay, const struct header* header) {

}

static struct header* relay_get_header(void* relay) {
  return NULL;
}

static int relay_get_body(void* relay, char** ptr_bldy, int* len_body) {
  return 0;
}

static int relay_write_body(void* relay, char* data, int len) {
  return 0;
}

static void relay_close(void* relay) {

}
struct relay_sys http2_relay_sys = {
  .relay_sys_init = relay_sys_init,
  .relay_create = relay_create,
  .relay_send_request = relay_send_request,
  .relay_get_header = relay_get_header,
  .relay_get_body = relay_get_body,
  .relay_write_body = relay_write_body,
  .relay_close = relay_close
};

