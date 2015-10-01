/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef __sgi
#define errx(exitcode, format, args...)                                        \
  {                                                                            \
    warnx(format, ##args);                                                     \
    exit(exitcode);                                                            \
  }
#define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#endif



#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "nghttp2.h"
#include "ep.h"
#include "util.h"
#include "header.h"
#include "relay.h"
#include "dns.h"
#include "list.h"
#include "ep_write_buf.h"

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
  list_head list;
  struct http2_stream_data *prev, *next;
  char *request_path;
  int32_t stream_id;
  int fd;
  struct header* request_header;
  char path[256];
  char scheme[50];
  char authority[256];
  void* relay;
  struct header* response_header;
  struct http2_session_data* session;

  bool is_body_recv;
  bool is_body_sent;
  int body_len;
  bool is_body_complete;
  bool is_request_completed;
  bool is_response_body_differ;

  list_head list_resquest_body_buf;
  list_head list_write_buf;
  bool has_body;

} http2_stream_data;

typedef struct http2_session_data {
  
  list_head list_streams;
  struct ep_file *bev;
  int client_fd;
  app_context *app_ctx;
  nghttp2_session *session;
  char *client_addr;
} http2_session_data;

struct app_context {
  int server_fd;
  struct ep_base *evbase;
};

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;


static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data) {
  list_add(&stream_data->list,  &session_data->list_streams);
}

static void remove_stream(http2_session_data *session_data,
                          http2_stream_data *stream_data) {
  list_del(&stream_data->list);
}

static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
  http2_stream_data *stream_data;
  stream_data = (http2_stream_data *)calloc(1, sizeof(http2_stream_data));
  memset(stream_data, 0, sizeof(http2_stream_data));
  stream_data->stream_id = stream_id;
  stream_data->fd = -1;
  stream_data->request_header = header_new(HEADER_REQUEST);
  add_stream(session_data, stream_data);
  INIT_LIST_HEAD(&stream_data->list_resquest_body_buf);
  INIT_LIST_HEAD(&stream_data->list_write_buf);
  return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  struct ep_write_buf* pos;
  struct ep_write_buf* n;

  list_for_each_entry_safe(pos, n, &stream_data->list_resquest_body_buf, list) {
    list_del(&pos->list);
    ep_write_buf_free(pos);
  }

  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }
  free(stream_data->request_path);
  free(stream_data);
}

static http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
  int rv;
  http2_session_data *session_data;
  char host[NI_MAXHOST] = {};
  int val = 1;

  session_data = (http2_session_data *)calloc(1, sizeof(http2_session_data));
  memset(session_data, 0, sizeof(http2_session_data));
  session_data->app_ctx = app_ctx;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

  rv = getnameinfo(addr, addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
  if (rv != 0) {
    session_data->client_addr = strdup("(unknown)");
  } else {
    session_data->client_addr = strdup(host);
  }

  INIT_LIST_HEAD(&session_data->list_streams);
  return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
  fprintf(stderr, "delete_http2_session_data\n");
  http2_stream_data *stream_data;
  http2_stream_data *n;
  ep_file_free(session_data->bev);
  nghttp2_session_del(session_data->session);
  list_for_each_entry_safe(stream_data, n, &session_data->list_streams,  list) {
    delete_http2_stream_data(stream_data);
  }
  free(session_data->client_addr);
  free(session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
  //fprintf()
  int rv;
  rv = nghttp2_session_send(session_data->session);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
  ssize_t readlen;
  unsigned char data[4096] = {};
  int datalen = recv(session_data->client_fd, data, sizeof(data), 0);
  fprintf(stderr, "recv:%d\n", datalen);

  if(datalen <= 0) {
    ep_file_detect(session_data->bev, 0, -1);
    return -1;
  }

  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);

  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }

  if (session_send(session_data) != 0) {
    return -1;
  }
  return 0;
}

static ssize_t send_callback(nghttp2_session *session , const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  // TODO: check sent data length
  int real = send(session_data->client_fd, (void*)data, length, 0);
  fprintf(stderr, "send_callback:%d=>%d\n", length, real);
  return length;
}


/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags ,
                              void *user_data ) {
  char sz_header[1024] = {};
  char sz_value[4096] = {};
  strncpy(sz_header, (char*)name, sizeof(sz_header));
  strncpy(sz_value, (char*)value, sizeof(sz_value));

  //fprintf(stderr, "on_header_callback,%s:%s\n", sz_header, sz_value);
  http2_stream_data *stream_data;
  const char PATH[] = ":path";
  if(frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }
  if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  stream_data = (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

  if (!stream_data || stream_data->request_path) {
    return 0;
  }

  if(strcasecmp(sz_header, ":path") == 0) {
    strncpy(stream_data->path, sz_value, sizeof(stream_data->path));
  } else if(strcmp(sz_header, ":method") == 0) {
    header_set_method(stream_data->request_header, sz_value);
  } else if(strcmp(sz_header, ":scheme") == 0) {
    strncpy(stream_data->scheme, sz_value, sizeof(stream_data->scheme));
  } else if(strcasecmp(sz_header, ":authority") == 0) {
    header_add_pair(stream_data->request_header, "host", sz_value);
    strncpy(stream_data->authority, sz_value, sizeof(stream_data->authority));
  } else {
    header_add_pair(stream_data->request_header, sz_header, sz_value);  
  }
  
  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  fprintf(stderr, "on_begin_headers_callback\n");
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data);
  return 0;
}


extern struct relay_sys http_relay_sys;

static void relay_make_nv(nghttp2_nv* nv, const char* name, const char* value) {
  nv->name = (uint8_t*)name;
  nv->namelen = strlen(name);
  nv->value = (uint8_t*)value;
  nv->valuelen = strlen(value);
}

static ssize_t relay_data_readcb(nghttp2_session *session ,
                                  int32_t stream_id , uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data ) {
  struct ep_write_buf* pos = NULL;
  struct ep_write_buf* n = NULL;
  http2_stream_data* stream_data = (http2_stream_data*)nghttp2_session_get_stream_user_data(session, stream_id);
  if(!stream_data) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  fprintf(stderr, "relay_data_cb, remote window=%d\n",
    nghttp2_session_get_stream_remote_window_size(stream_data->session->session, stream_data->stream_id));
  if(list_empty(&stream_data->list_write_buf)) {

    if(stream_data->is_body_complete) {
      (*data_flags) |= NGHTTP2_DATA_FLAG_EOF;
      fprintf(stderr, "relay_data_readcb:all body sent\n");
      return 0;
    } else {
      int local = nghttp2_session_get_stream_effective_local_window_size(stream_data->session->session, stream_data->stream_id);
      fprintf(stderr, "relay_data_readcb:no body differed:%d\n", local);
      stream_data->is_response_body_differ = true;
      return NGHTTP2_ERR_DEFERRED;

    }
  }

  int cpy_len = ep_write_buf_read(&stream_data->list_write_buf, (char*)buf, length);

  if(stream_data->is_body_complete && list_empty(&stream_data->list_write_buf)) {
      (*data_flags) |= NGHTTP2_DATA_FLAG_EOF;
    fprintf(stderr, "body complete\n");
  }
  fprintf(stderr, "body sent:%d\n", cpy_len);
  return cpy_len;
}


static void relay_header_complete(http2_stream_data *stream_data) {
  nghttp2_data_provider provider = {
    .read_callback = relay_data_readcb
  };
  int i = 1;
  struct field* pos = NULL;
  stream_data->response_header = http_relay_sys.relay_get_header(stream_data->relay);
  char sz_status_code[16] = {};
  snprintf(sz_status_code, sizeof(sz_status_code), "%d", stream_data->response_header->status_code);
  nghttp2_nv nvs[50] = {};
  relay_make_nv(nvs, ":status", sz_status_code);
  bool is_body = false;
  fprintf(stderr, "status:%s\n", sz_status_code);

  if(strcasecmp(stream_data->request_header->method, "connect") == 0) {
    is_body = true;
  }
  
  list_for_each_entry(pos, &stream_data->response_header->list_headers, list) {
    fprintf(stderr, "%s:%s\n", pos->field, pos->value);
    
    if(strcasecmp(pos->field, "proxy-connection") == 0) {
      continue;
    }

    if(strcasecmp(pos->field, "Transfer-Encoding") == 0) {
      is_body = true;
      continue;
    }

    if(strcasecmp(pos->field, "content-length") == 0) {
      is_body = true;
    }

    if(strcasecmp(pos->field, "Connection") == 0) {
      continue;
    }

    if(strcasecmp(pos->field, "Keep-Alive") == 0) {
      continue;
    }    

    relay_make_nv(nvs + i, pos->field, pos->value);
    i++;
  }

  if(!is_body) {
    provider.read_callback = NULL;
  }
  
  nghttp2_submit_response(stream_data->session->session, stream_data->stream_id, nvs, i, &provider);
  nghttp2_session_send(stream_data->session->session);
}

static void relay_body(http2_stream_data *stream_data) {
  char* body = NULL;
  int len = 0;
  fprintf(stderr, "relay_body, session=%p, streamid=%d\n", stream_data->session->session, stream_data->stream_id);
  stream_data->has_body = true;
  http_relay_sys.relay_get_body(stream_data->relay, &body, &len);

  struct ep_write_buf* buf = ep_write_buf_create(body, len);
  list_add_tail(&buf->list, &stream_data->list_write_buf);

  if(stream_data->is_response_body_differ) {
    stream_data->is_response_body_differ = false;
    int res = nghttp2_session_resume_data(stream_data->session->session, stream_data->stream_id);

    fprintf(stderr, "resume res=%d\n", res);
    if(res == 0) {
       res = nghttp2_session_send(stream_data->session->session);
    fprintf(stderr, "send res=%d\n", res);
    } 
  }
}

static void relay_connected(http2_stream_data *stream_data) {
  struct ep_write_buf* pos;
  struct ep_write_buf* n;
  http_relay_sys.relay_send_request(stream_data->relay, stream_data->request_header);

  list_for_each_entry_safe(pos, n, &stream_data->list_resquest_body_buf, list) {
    fprintf(stderr, "writting pending req body:%d\n", pos->len_total);
    http_relay_sys.relay_write_body(stream_data->relay, pos->buf, pos->len_total);
    list_del(&pos->list);
    ep_write_buf_free(pos);
  }  
}

static void relaycb(void* relay, short what, void* args) {
  http2_stream_data *stream_data = (http2_stream_data *)args;
  if(what == RELAY_CONNECTED) {
    fprintf(stderr, "relay connected,sending request:%s\n", stream_data->request_header->url);
    relay_connected(stream_data);

  } else if(what == RELAY_HEADER_COMPLETE) {
    fprintf(stderr, "header complete\n");
    relay_header_complete(stream_data);
  } else if(what == RELAY_BODY) {
    relay_body(stream_data);
  } else if(what == RELAY_MSG_COMPLETE) {
    fprintf(stderr, "msg complete\n");
    stream_data->is_body_complete = true;
    if(stream_data->body_len == 0) {
      nghttp2_session_resume_data(stream_data->session->session, stream_data->stream_id);
      nghttp2_session_send(stream_data->session->session);
    }
    stream_data->relay = NULL;
  } else if(what == RELAY_ERR_DNS_FAILED || RELAY_ERR_CONN_FAILED) {
    //nghttp2_submit_rst_stream(stream_data->session->session, 0, stream_data->stream_id, 0);
    nghttp2_nv nvs[5] = {
      MAKE_NV(":status", "503"),
      MAKE_NV("x-error-reason", "connect source failed"),
    };
    nghttp2_submit_response(stream_data->session->session, stream_data->stream_id, nvs, 2, NULL);
    nghttp2_session_send(stream_data->session->session);
  } else if(what == RELAY_ERR_CONN_TERMINATE) {
    nghttp2_submit_rst_stream(stream_data->session->session, 0, stream_data->stream_id, 0);
    nghttp2_session_send(stream_data->session->session);
  }
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags, int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data) {
  fprintf(stderr, "relay_on_data_chunk_recv_callback, stream id=%d\n", stream_id);
  http2_stream_data* stream_data =
          (http2_stream_data *)nghttp2_session_get_stream_user_data(session, stream_id);
  int status = http_relay_sys.relay_get_status(stream_data->relay);

  if(len <= 0) {
    return 0;
  }


  if(status >= RELAY_STATUS_CONNECTED) {
    http_relay_sys.relay_write_body(stream_data->relay, (char*)data, len);
    int local_data_len = nghttp2_session_get_stream_effective_local_window_size(stream_data->session->session, stream_data->stream_id);

    if(local_data_len > 30000) {
      nghttp2_submit_window_update(stream_data->session->session, 0, stream_data->stream_id, local_data_len);
    }
  } else {
    fprintf(stderr, "saving pending req body");
    struct ep_write_buf* buf = ep_write_buf_create((char*)data, len);
    list_add_tail(&stream_data->list_resquest_body_buf, &buf->list);
  }

  return 0;
}



static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
  
  stream_data->session = session_data;
  char url[1024 * 2] = {};
  char host[1024] = {};
  strncpy(host, stream_data->authority, sizeof(host));
  char* pos = strchr(host, ':');
  *pos = 0;
  append_format(url, sizeof(url), "%s://%s%s", stream_data->scheme, stream_data->authority, stream_data->path);
  header_set_url(stream_data->request_header, url, strlen(url));

  if(strcasecmp(stream_data->request_header->method, "post") == 0) {
    const char* content_length = header_value(stream_data->request_header, "content-length");

    if(content_length == NULL) {
      header_add_pair(stream_data->request_header, "Transfer-Encoding", "chunked");
    }
  }

  fprintf(stderr, "on_request_recv:%s\n", url);
  stream_data->relay = http_relay_sys.relay_create(host, atoi(pos + 1), relaycb, stream_data);

  return 0;
}

static void on_request_complete(http2_stream_data *stream_data) {
  int status = http_relay_sys.relay_get_status(stream_data->relay);
  if(status >= RELAY_STATUS_CONNECTED) {
    http_relay_sys.relay_complete_request(stream_data->relay);
  } else {
    stream_data->is_request_completed = true;
  }
}
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  fprintf(stderr, "on_frame_recv_callback:%d\n", frame->hd.type);
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    break;
  case NGHTTP2_HEADERS:
  {
    /* Check that the client request has finished */
    fprintf(stderr, "NGHTTP2_HEADERS:%d\n", frame->headers.nvlen);

    if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      stream_data =
          (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      if (!stream_data) {
        return 0;
      }
      return on_request_recv(session, session_data, stream_data);
    }

    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data =
          (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

      if (!stream_data) {
        return 0;
      }

    }
    break;
  }

  case NGHTTP2_WINDOW_UPDATE: {
    fprintf(stderr, "recv window update package,len=%d\n", frame->window_update.window_size_increment);
    stream_data =
          (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data) {
        return 0;
      }
    http_relay_sys.relay_resume_read(stream_data->relay);
    break;
  }
  case NGHTTP2_RST_STREAM: {
    stream_data =
          (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if(stream_data && stream_data->relay) {
      http_relay_sys.relay_close(stream_data->relay);
      stream_data->relay = NULL;
    }
    break;
  }
  default:
    break;
  }
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code , void *user_data) {

  fprintf(stderr, "stream closed\n");
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;

  stream_data = (http2_stream_data *)nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_data) {
    return 0;
  }

  remove_stream(session_data, stream_data);
  return 0;
}

ssize_t on_data_source_read_length_callback(
    nghttp2_session *session, uint8_t frame_type, int32_t stream_id,
    int32_t session_remote_window_size, int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size, void *user_data) {
  fprintf(stderr, "relay_session_data_source_read_length_callback:remote=%d\n", stream_remote_window_size);
  return 12345;
}


static void initialize_nghttp2_session(http2_session_data *session_data) {
  nghttp2_session_callbacks *callbacks;

  nghttp2_option* opt = NULL;

  nghttp2_option_new(&opt);

  nghttp2_option_set_no_auto_window_update(opt, 1);

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback);

  nghttp2_session_server_new2(&session_data->session, callbacks, session_data, NULL);

  nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

static void readcb(http2_session_data *session_data) {
  //http2_session_data *session_data = (http2_session_data *)ptr;
  if (session_recv(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

static void writecb(http2_session_data *session_data) {

  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data(session_data);
    return;
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

/* eventcb for bufferevent */
static void eventcb(struct ep_file* file, int fd, short events, void *ptr) {
  fprintf(stderr, "eventcb:%d\n", events);
  http2_session_data *session_data = (http2_session_data *)ptr;

  if(events & EP_ERROR) {
    ep_file_detect(session_data->bev, 0, -1);
    delete_http2_session_data(session_data);
  } else if(events == EP_READ) {
    fprintf(stderr, "read\n");
    readcb(session_data);
  } else if(events == EP_WRITE) {
    writecb(session_data);
  } else if(events & EP_ERROR) {
   
  }
}

static void acceptcb(struct ep_file* file, int fd, short what, void* args) {
  struct sockaddr addr = {};
  socklen_t len = sizeof(struct sockaddr);
  app_context *app_ctx = (app_context *)args;
  http2_session_data *session_data;

 
  int client_fd = accept(app_ctx->server_fd, &addr, &len);
  session_data = create_http2_session_data(app_ctx, client_fd, &addr, len);
  session_data->bev = ep_file_create(app_ctx->evbase, client_fd, eventcb, session_data);
  session_data->client_fd = client_fd;
  initialize_nghttp2_session(session_data);
  if (send_server_connection_header(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
  }
  ep_file_detect(session_data->bev, EP_READ, -1);
}

static int start_listen(struct ep_base *evbase, int port,
                         app_context *app_ctx) {

  int opt_reuse = 1;
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  make_socket_nonblocking(fd);
  struct sockaddr_in addr = {};
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(int));
  if(bind(fd, (struct sockaddr *) & addr, sizeof(struct sockaddr_in)) != 0) {
    close(fd);
    return -1;
  }

  if(listen(fd, 20) != 0) {
    close(fd);
    return -1;
  }
  app_ctx->evbase = evbase;
  app_ctx->server_fd = fd;
  struct ep_file* file = ep_file_create(evbase, fd, acceptcb, app_ctx);
  ep_file_detect(file, EP_READ, -1); 
}

static void initialize_app_context(app_context *app_ctx,
                                   struct ep_base *evbase) {
  memset(app_ctx, 0, sizeof(app_context));
  app_ctx->evbase = evbase;
}

void h2_server_run(int port) {
  app_context app_ctx;
  struct ep_base *evbase = NULL;

  evbase = ep_base_create();
  dns_init(evbase, "114.114.114.114");
  http_relay_sys.relay_sys_init(evbase);
  initialize_app_context(&app_ctx, evbase);
  start_listen(evbase, port, &app_ctx);
  ep_base_dispatch(evbase);
  ep_base_free(evbase);
}

int main() {
  h2_server_run(6666);
}