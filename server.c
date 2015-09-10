#include "ep.h"
#include "sys_network.h"
#include "util.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "relay.h"
#include "http_parser.h"
#include "header.h"
#include "dns.h"
#include "client.h"

static int s_listen_fd = 0;
static int s_channel[2] = {};
static struct ep_file* s_channel_file = NULL;
static struct ep_file* s_listen_file = NULL;
static struct ep_base* s_base = NULL;
static pthread_t s_thread_dispatch;

static void channel_cb(struct ep_file* file, int fd, short what, void* args);

static void timer_cb(struct ep_timer* timer, void* args) {
  fprintf(stderr, "timercb\n");
}
static void listen_cb(struct ep_file* file, int fd, short what, void* args) {
  if(what != EP_READ) {
    return;
  }
  fprintf(stderr, "accept a client\n");
  struct sockaddr_in addr = {};
  socklen_t len_addr = sizeof(struct sockaddr_in);
  int client_fd = accept(fd, (struct sockaddr*)&addr, &len_addr);
  client_handle_fd(client_fd);
}

static void server_dnscb(int ret_code, const char** ips, int count, const char* cname, void* args) {
  printf("server_dnscb,ret=%d,1st ip=%s,cname=%s\n", ret_code, ips ? ips[0] : "", cname);
}

static void channel_cb(struct ep_file* file, int fd, short what, void* args) {
  if(what & EP_READ) {

    char data[255] = {};
    int len = read(fd, data, sizeof(data));

    if(len == 0) {
      ep_file_detect(file, 0, -1);
    }

    if(strcmp(data, "exit") == 0) {
      ep_base_stop(s_base);
    }
    printf("channel_cb:len=%d, str=%s\n",len,  data);
  }
  
}

static void* server_do_dispatch(void* args) {
  fprintf(stderr, "server_do_dispatch start\n");
  ep_base_dispatch(s_base);
  dns_fini();
  
  ep_file_free(s_channel_file);
  ep_file_free(s_listen_file);
  close(s_channel[0]);
  close(s_channel[1]);
  close(s_listen_fd);
  ep_base_free(s_base);
  fprintf(stderr, "server_do_dispatch complete\n");
  return NULL;
}

static int server_create_listen_fd(int port) {
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
  return fd;
}

int server_start() {
  s_base = ep_base_create();
  pipe(s_channel);  
  make_socket_nonblocking(s_channel[0]);
  s_channel_file = ep_file_create(s_base, s_channel[0], channel_cb, NULL);
  s_listen_fd = server_create_listen_fd(8123);
  s_listen_file = ep_file_create(s_base, s_listen_fd, listen_cb, NULL);

  ep_file_detect(s_channel_file, EP_READ, -1);
  ep_file_detect(s_listen_file, EP_READ, -1);
  dns_init(s_base, "114.114.114.114");
  client_init(s_base);
  server_do_dispatch(NULL);
  //pthread_create(&s_thread_dispatch, NULL, server_do_dispatch, NULL);
  //pthread_detach(s_thread_dispatch);
  return 0;
}

extern void h2_server_run(int port);

int main() {
  /*
  char cmd[255] = {};
  server_start();
  while(strcmp(cmd, "exits") != 0) {
    scanf("%s", cmd);
    printf("read %s\n", cmd);
    write(s_channel[1], cmd, strlen(cmd));
  }
}*/
  
  h2_server_run(6666);
}