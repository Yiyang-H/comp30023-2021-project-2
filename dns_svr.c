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

/* typedef struct {

}dns_message_t; */

int main(int argc, char** argv) {
    if(argc < 3) {
        perror("command line arg");
        exit(EXIT_FAILURE);
    }

    int sockfd, newsockfd;
	struct addrinfo hints, *res;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

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
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // bind address to socket
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

    // Listen on socket - means we're ready to accept connections,
	if (listen(sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

    // Accept a connection - blocks until a connection is ready to be accepted
	// Get back a new file descriptor to communicate on
	client_addr_size = sizeof client_addr;
	newsockfd =
		accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
	if (newsockfd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

    // Need to read 

/*     unsigned char buffer[256];
    int n = read(newsockfd, buffer, 256);

    for(int i = 0; i < n; i++) {
        printf("%02d ",buffer[i]);
    }
    printf("\n"); */

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

    printf("Connected to upstream server\n");

    unsigned char buffer[256];
    int n = read(newsockfd, buffer, 256);
    write(upstream_sockfd, buffer, 256);

    printf("First n: %d\n",n);

    unsigned char recieve_buffer[256];
    n = read(upstream_sockfd, recieve_buffer, 256);

    printf("Second n: %d\n",n);

    for(int i = 0; i < n; i++) {
        printf("%02x ",recieve_buffer[i]);
    }
    printf("\n");

    write(newsockfd, recieve_buffer, 256);


    



    // int bytes_sent = 0;
    // do {
	// 	bytes_sent = sendfile(upstream_sockfd, newsockfd, NULL, 2048);
	// } while (bytes_sent > 0);
	// if (bytes_sent < 0) {
	// 	perror("sendfile1");
	// 	exit(EXIT_FAILURE);
	// }
    // do {
	// 	bytes_sent = sendfile(newsockfd, upstream_sockfd, NULL, 2048);
	// } while (bytes_sent > 0);
	// if (bytes_sent < 0) {
	// 	perror("sendfile");
	// 	exit(EXIT_FAILURE);
	// }



    return 0;
}



// // Reads a dns message 
// dns_message_t read_message(int fd) {
    
//     /* Define a buffer of 2 bytes to store a header */
//     unsigned char head_buffer[2];
//     short *header = (void*) head_buffer;
//     int bytes_read = read(fd, head_buffer, 2);
    
//     *header = ntohs(*header);

//     /* Define a buffer with size given in header */
//     unsigned char buffer[*header];
//     bytes_read = read(0, buffer, *header);

//     /* Header of the message */
//     short *ID = (void*) buffer;
//     *ID = ntohs(*ID);
//     bool QR = (buffer[2] >> 7) & 1;

//     char opcode = (buffer[2] >> 3) & (16-1);
//     bool AA = (buffer[2] >> 2) & 1;
//     bool TC = (buffer[2] >> 1) & 1;
//     bool RD = buffer[2] & 1;

//     // printf("ID: %d, QR: %d, OP: %d, AA: %d, TC: %d, RD: %d\n", *ID, QR, opcode, AA, TC, RD);

//     bool RA = (buffer[3] >> 7) & 1;
//     char Z = (buffer[3] >> 4) & (8-1);
//     char rcode = buffer[3] & (16-1);
//     // printf("RA: %d, Z: %d, RCODE: %d\n", RA, Z, rcode);

//     short *qdcount = (void*) buffer+4;
//     short *ancount = (void*) buffer+6;
//     short *nscount = (void*) buffer+8;
//     short *arcount = (void*) buffer+10;
//     *qdcount = ntohs(*qdcount);
//     *ancount = ntohs(*ancount);
//     *nscount = ntohs(*nscount);
//     *arcount = ntohs(*arcount);
//     // printf("QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d\n", *qdcount, *ancount, *nscount, *arcount);
    
//     char* time = "2021-04-24T05:12:32+0000 ";
//     printf("%s",time);

//     /* parse Question section */
//     unsigned char* current_byte = buffer+12;
//     char qname[255];
//     int qname_buddy = 0;
//     if(qdcount) {
//         /* Loop until length of the label become 0 */
//         unsigned char length = *current_byte;
//         current_byte += 1;
//         while(length) {
//             for(;length > 0; length--) {
                
//                 qname[qname_buddy++] = *current_byte;
//                 current_byte += 1;
//             }
//             qname[qname_buddy++] = '.';
//             length = *current_byte;
//             current_byte += 1;


//             /* for(int i = 0; i < length; i++) {
//                 printf("%d ", label[i]);
//             } */
//         }
//         qname[qname_buddy-1] = '\0';
        
//     }
//     /* current_byte points to qtype */
//     short *qtype = (void*) current_byte;
//     *qtype = ntohs(*qtype);


//     current_byte += 2;
//     short *qclass = (void*) current_byte;
//     *qclass = ntohs(*qclass);

// }