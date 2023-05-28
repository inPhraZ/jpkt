prefix := /usr/local
libdir := ${prefix}/lib
includedir := ${prefix}/include

rootdir := $(PWD)
SRC := ${rootdir}/src
INC := ${rootdir}/include
BIN := ${rootdir}/bin
LIB := ${rootdir}/lib
EXM := ${rootdir}/examples

MAJOR := 1
MINOR := 0
PROG := libjpkt
LIBJPKT := $(PROG).$(MAJOR).$(MINOR)

CC := gcc
AR := ar

CFLAGS := -O2 -Wall -Werror -fPIC
ARFLAGS := -rcs

DEPS = \
	$(shell pkg-config --libs libpcap glib-2.0 json-glib-1.0)	\
	$(shell pkg-config --cflags glib-2.0 json-glib-1.0)

OBJS :=				\
	jpkt.o			\
	jpkt-packet.o	\
	jpkt-queue.o	\
	jpkt-eth.o		\
	jpkt-arp.o		\
	jpkt-ip.o		\
	jpkt-udp.o		\
	jpkt-tcp.o		\
	jpkt-icmp.o		\
	jpkt-data.o

.PHONY: lib

lib: 
	mkdir -p $(LIB) $(BIN)
	$(CC) $(CFLAGS) -c $(SRC)/*.c -I $(INC) $(DEPS)
	$(CC) -shared -o $(LIB)/$(LIBJPKT).so $(OBJS)
	$(AR) $(ARFLAGS) $(LIB)/$(LIBJPKT).a $(OBJS)
	mv $(OBJS) $(BIN)

example: lib
	$(CC) $(CFLAGS) -g $(EXM)/$@.c $(LIB)/$(LIBJPKT).so -o $(EXM)/$@ -I $(INC) $(DEPS)

install: lib
	@echo
	@echo install

uninstall:
	@echo Uninstall

clean:
	rm -rf $(BIN)

cleanall: clean
	rm -rf $(LIB)
	rm -rf $(EXM)/example
