CFLAGS=-Wall -ansi -std=c99

dns_svr: dns_svr.c
	gcc $(CFLAGS) -o dns_svr dns_svr.c
clean:
	rm -f dns_svr