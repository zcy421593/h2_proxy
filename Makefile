TARGET = h2_proxy

INCLUDES = -I./nghttp2/includes/ \
	-I./nghttp2/includes/nghttp2/

DEPS = ep.o \
	ep_poll_epoll.o \
	util.o \
	dns.o \
	header.o \
	http_parser.o \
	relay_http.o \
	h2_server.o \
	conn_tcp.o \
	ep_buf_tcp.o \
	ep_write_buf.o


CFLAGS = -g \
	$(INCLUDES) \
	-fPIC

STATIC_LIBRARIES = nghttp2/libnghttp2.a

epoll_server: $(DEPS) $(STATIC_LIBRARIES)
	$(CC) -lrt -lpthread $(DEPS) $(STATIC_LIBRARIES) -o $(TARGET)

nghttp2/libnghttp2.a:
	make -C nghttp2/

clean:
	rm -f $(DEPS) $(TARGET)
	make clean -C nghttp2/