CFLAGS=-Wall -ansi -std=c99

dns_svr: dns_svr.o dns_message.o
	gcc $(CFLAGS) -o dns_svr dns_svr.o dns_message.o

dns_svr.o: dns_svr.c dns_message.h
	gcc $(CFLAGS) -c dns_svr.c

dns_message.o: dns_message.c dns_message.h
	gcc $(CFLAGS) -c dns_message.c

clean:
	rm -f dns_svr
	rm -f *.o