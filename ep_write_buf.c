#include "ep_write_buf.h"
#include <stdlib.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
struct ep_write_buf* ep_write_buf_create(char* buf, int len) {
  assert(buf);
  assert(len);
  struct ep_write_buf* write_buf = (struct ep_write_buf*)calloc(1, sizeof(struct ep_write_buf));
  write_buf->buf = (char*)malloc(len);
  memcpy(write_buf->buf, buf, len);
  write_buf->len_total = len;
  INIT_LIST_HEAD(&write_buf->list);
  return write_buf;
}

void ep_write_buf_free(struct ep_write_buf* buf) {
  free(buf->buf);
  free(buf);
}