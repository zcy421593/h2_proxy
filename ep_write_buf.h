#include "list.h"
struct ep_write_buf {
  list_head list;
  char* buf;
  int len_total;
  int len_sent;
};

struct ep_write_buf* ep_write_buf_create(char* buf, int len);
void ep_write_buf_free(struct ep_write_buf* buf);
int ep_write_buf_read(list_head* head, char* buf, int len);