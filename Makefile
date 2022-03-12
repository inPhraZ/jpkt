OBJS = reponet-main.o	\
	   reponet-packet.o	\
	   reponet-eth.o	\
	   reponet-arp.o	\
	   reponet-ip.o		\
	   reponet-icmp.o

LIBS = 	$(shell pkg-config --libs libpcap glib-2.0 json-glib-1.0)

INC = $(shell pkg-config --cflags glib-2.0 json-glib-1.0)

reponet: $(OBJS)
	gcc -o reponet $(OBJS) $(LIBS)

reponet-main.o: reponet-main.c
	gcc -c reponet-main.c

reponet-packet.o: reponet-packet.c reponet-packet.h
	gcc -c reponet-packet.c $(INC)

reponet-eth.o: reponet-eth.c reponet-eth.h
	gcc -c reponet-eth.c $(INC)

reponet-arp.o: reponet-arp.c reponet-arp.h
	gcc -c reponet-arp.c $(INC)

reponet-ip.o: reponet-ip.c reponet-ip.h
	gcc -c reponet-ip.c $(INC)

reponet-icmp.o: reponet-icmp.c reponet-icmp.h
	gcc -c reponet-icmp.c $(INC)

clean:
	rm -rf ./*.o
