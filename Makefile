OBJS = reponet-main.o 	\
	   reponet-packet.o \

LIBS = 	$(shell pkg-config --libs libpcap glib-2.0 json-glib-1.0)

INC = $(shell pkg-config --cflags glib-2.0 json-glib-1.0)

reponet: $(OBJS)
	gcc -o reponet $(OBJS) $(LIBS)

reponet-main.o: reponet-main.c
	gcc -c reponet-main.c

reponet-packet.o: reponet-packet.c reponet-packet.h
	gcc -c reponet-packet.c $(INC)

clean:
	rm -rf ./*.o
