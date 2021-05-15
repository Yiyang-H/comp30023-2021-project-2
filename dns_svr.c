#define _POSIX_C_SOURCE 200112L

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/sendfile.h>

#define PORT "8053"
#define MAX_DOMAIN_LENGTH 253

// DNS header, only store information needed for this project
// 
typedef struct {
    uint16_t ID;
    uint16_t QDCOUNT, ANCOUNT;
}dns_header_t;

typedef struct {
    char QNAME[MAX_DOMAIN_LENGTH + 1];
    uint16_t QTYPE, QCLASS;
}dns_question_t;

typedef struct {
    char ANAME[MAX_DOMAIN_LENGTH + 1];
    uint16_t ATYPE, ACLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    // store ipv6
}dns_answer_t;

typedef struct {
    dns_header_t header;
    dns_question_t question;
    dns_answer_t answer;
}dns_message_t;


dns_message_t read_message(uint16_t header, uint8_t* raw_message);
uint16_t read_two_bytes(uint8_t* start);

int main(int argc, char** argv) {
    if(argc < 3) {
        perror("usage: ./dns_svr server_ip port");
        exit(EXIT_FAILURE);
    }


    int listen_sockfd;
	struct addrinfo hints, *res;

    // Create address we're going to listen on (with given port number)
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int s = getaddrinfo(NULL, PORT, &hints, &res);
    if(s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
    }

    // create socket
	listen_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (listen_sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    int enable = 1;
    if (setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // bind address to socket
	if (bind(listen_sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
    freeaddrinfo(res);

    // Listen on socket - means we're ready to accept connections,
	if (listen(listen_sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
        
	}
    int newsockfd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    client_addr_size = sizeof client_addr;
    while(1){

        // Accept a connection - blocks until a connection is ready to be accepted
        // Get back a new file descriptor to communicate on
        newsockfd =
            accept(listen_sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (newsockfd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        /* 
        Connection established with client
        Need to read() dns message from client
        Handle the dns message: check QType in question section
        If AAAA request, connect to upstream dns
        */

        uint8_t header_buffer[2];
        read(newsockfd, header_buffer, 2);
        uint16_t size = read_two_bytes(header_buffer);

        uint8_t body_buffer[size];
        read(newsockfd, body_buffer, size);
        dns_message_t dns_message = read_message(size, body_buffer);

        if(dns_message.question.QTYPE != 28) {
            /*
            Not a AAAA requst, modify the header and return 
            */
            // printf("not a AAAA request\n");

            // Set QR to 1
            body_buffer[2] = body_buffer[2] | 128;

            // Set RCODE to 4
            body_buffer[3] = (body_buffer[3] & 240) | 4;

            // Sent back to the client
            write(newsockfd, header_buffer, 2);
            write(newsockfd, body_buffer, size);

        }else {
            /*
            Yes, AAAA request, send it to upstream server 
            */

            // Create a socket to connet to server
            int upstream_sockfd;
            struct addrinfo upstream_hints, *upstream_servinfo, *upstream_rp;

            memset(&upstream_hints, 0, sizeof upstream_hints);
            upstream_hints.ai_family = AF_INET;
            upstream_hints.ai_socktype = SOCK_STREAM;
            s = getaddrinfo(argv[1], argv[2], &upstream_hints, &upstream_servinfo);
            if (s != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }

            for (upstream_rp = upstream_servinfo; upstream_rp != NULL; upstream_rp = upstream_rp->ai_next) {
                upstream_sockfd = socket(upstream_rp->ai_family, upstream_rp->ai_socktype, upstream_rp->ai_protocol);
                if (upstream_sockfd == -1)
                    continue;

                if (connect(upstream_sockfd, upstream_rp->ai_addr, upstream_rp->ai_addrlen) != -1)
                    break; // success

                close(upstream_sockfd);
            }
            if (upstream_rp == NULL) {
                fprintf(stderr, "client: failed to connect\n");
                exit(EXIT_FAILURE);
            }
            freeaddrinfo(upstream_servinfo);

            write(upstream_sockfd, header_buffer, 2);
            write(upstream_sockfd, body_buffer, size);


            unsigned char recieve_buffer[256];
            read(upstream_sockfd, recieve_buffer, 256);

            // printf("Second n: %d\n",n);

            // for(int i = 0; i < n; i++) {
            //     printf("%02x ",recieve_buffer[i]);
            // }
            // printf("\n");

            write(newsockfd, recieve_buffer, 256);
            close(upstream_sockfd);
        }
        
        close(newsockfd);
    }
    close(listen_sockfd);
    return 0;
}



// Reads a dns message
// 
dns_message_t read_message(uint16_t header, uint8_t* raw_message) {
    dns_message_t dns_message;
    dns_header_t dns_header;
    dns_question_t dns_question;
    // dns_answer_t dns_answer;

    uint8_t* current = raw_message;
    dns_header.ID = read_two_bytes(current);

    // Now points to the 4th byte
    current += 4;

    dns_header.QDCOUNT = read_two_bytes(current);
    
    // Now points to the 6th byte
    current += 2;
    dns_header.ANCOUNT = read_two_bytes(current);

    // Now points to the 12th byte, start of question section
    current += 6;

    int n = *current;
    current++;
    int buddy = 0;
    while(n) {
        dns_question.QNAME[buddy++] = *current;
        current++;
        n--;
        if(n == 0) {
            dns_question.QNAME[buddy++] = '.';
            n = *current;
            current++;
        }
    }
    dns_question.QNAME[buddy - 1] = '\0';

    // current should now be pointing to QTYPE
    dns_question.QTYPE = read_two_bytes(current);

    // Now points to the start of answer section
    current += 4;
    if(dns_header.ANCOUNT) {
        // Read the answer section
    }

    dns_message.header = dns_header;
    dns_message.question = dns_question;

    return dns_message;
}

uint16_t read_two_bytes(uint8_t* start) {
    uint16_t* two_byte = (void*) start;
    return ntohs(*two_byte);
}

