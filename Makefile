OBJS = jpkt-main.o		\
	   jpkt-packet.o	\
	   jpkt-queue.o		\
	   jpkt-eth.o		\
	   jpkt-arp.o		\
	   jpkt-ip.o		\
	   jpkt-udp.o		\
	   jpkt-tcp.o		\
	   jpkt-icmp.o		\
	   jpkt-data.o

LIBS = 	$(shell pkg-config --libs libpcap glib-2.0 json-glib-1.0)

INC = $(shell pkg-config --cflags glib-2.0 json-glib-1.0)

jpkt: $(OBJS)
	gcc -o jpkt $(OBJS) $(LIBS)

jpkt-main.o: jpkt-main.c
	gcc -c jpkt-main.c

jpkt-packet.o: jpkt-packet.c jpkt-packet.h
	gcc -c jpkt-packet.c $(INC)

jpkt-queue.o: jpkt-queue.c jpkt-queue.h
	gcc -c jpkt-queue.c $(INC)

jpkt-eth.o: jpkt-eth.c jpkt-eth.h
	gcc -c jpkt-eth.c $(INC)

jpkt-arp.o: jpkt-arp.c jpkt-arp.h
	gcc -c jpkt-arp.c $(INC)

jpkt-ip.o: jpkt-ip.c jpkt-ip.h
	gcc -c jpkt-ip.c $(INC)

jpkt-icmp.o: jpkt-icmp.c jpkt-icmp.h
	gcc -c jpkt-icmp.c $(INC)

jpkt-udp.o: jpkt-udp.c jpkt-udp.h
	gcc -c jpkt-udp.c $(INC)

jpkt-tcp.o: jpkt-tcp.c jpkt-tcp.h
	gcc -c jpkt-tcp.c $(INC)

jpkt-data.o: jpkt-data.c jpkt-data.h
	gcc -c jpkt-data.c $(INC)

clean:
	rm -rf ./*.o
