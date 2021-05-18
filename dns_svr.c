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
#include <assert.h>
#include <time.h>


#include "dns_message.h"

#define PORT "8053"
#define TIMESTAMP_LENGTH 24
#define MAX_DOMAIN_LENGTH 253
#define NUM_OF_CACHE_ENTRY 5
#define LENGTH_OF_ANSWER_SECTION 16

#define CACHE
#define NONBLOCKING



// A cache_entry should contain a AAAA type question and its answer
// and cached time
typedef struct {
    dns_message_t message;
    time_t cache_time;
}cache_entry_t;


void get_timestamp(char* timestamp);
void get_specific_timestamp(char* timestamp, time_t time);
void cache_evication(cache_entry_t* cache, dns_message_t message, FILE* log);
bool is_answer_expired(cache_entry_t entry);
uint32_t read_four_bytes(uint8_t* start);
int search_in_cache(cache_entry_t* cache, char* QNAME);


int main(int argc, char** argv) {
    if(argc < 3) {
        perror("usage: ./dns_svr server_ip port");
        exit(EXIT_FAILURE);
    }

    FILE* log = fopen("./dns_svr.log", "w");

    cache_entry_t cache[NUM_OF_CACHE_ENTRY];
    for(int i = 0; i < NUM_OF_CACHE_ENTRY; i++) {
        cache[i].cache_time = 0;
    }

    int listen_sockfd;
	struct addrinfo hints, *res;

    char timestamp[TIMESTAMP_LENGTH+1];

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

    // initialise an active file descriptors set
	fd_set masterfds;
	FD_ZERO(&masterfds);
	FD_SET(listen_sockfd, &masterfds);
	// record the maximum socket number
	int maxfd = listen_sockfd;

    int map_upstream_to_client[FD_SETSIZE];

    
    while(true){
        // monitor file descriptors
		fd_set readfds = masterfds;
		if (select(FD_SETSIZE, &readfds, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}

        for(int i = 0 ; i <= maxfd; i++) {
            // Check if current fd is active
            if(FD_ISSET(i, &readfds)) {
                // Determine if current fd is which one of the following:
                // 1. The passive socket waiting to be connected
                // 2. A client socket sending request
                // 3. A server socket sending response

                if(i == listen_sockfd) {
                    // If new connection coming in, establish the connection
                    int newsockfd;
                    struct sockaddr_storage client_addr;
                    socklen_t client_addr_size;
                    client_addr_size = sizeof client_addr;

                    // Accept a connection - blocks until a connection is ready to be accepted
                    // Get back a new file descriptor to communicate on
                    newsockfd =
                        accept(listen_sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
                    if (newsockfd < 0) {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }else {
                        // add the socket to the set
						FD_SET(newsockfd, &masterfds);
						// update the maximum tracker
						if (newsockfd > maxfd)
							maxfd = newsockfd;
                    }


                }else {
                    // Read the dns_message first, determine if it a req or response
                    dns_message_t dns_message = read_message(i);
                    if(dns_message.header.QR == 0) {
                        // A request, check in cache, or connect to upstream

                        get_timestamp(timestamp);
                        fprintf(log, "%s requested %s\n", timestamp, dns_message.question.QNAME);
                        fflush(log);

                        // The body of the dns packet
                        uint8_t* body = dns_message.packet_body;

                        if(dns_message.question.QTYPE != 28) {
                            /*
                            Not a AAAA requst, modify the header and return 
                            */
                            get_timestamp(timestamp);
                            fprintf(log, "%s unimplemented request\n", timestamp);
                            fflush(log);

                            // Set QR to 1
                            body[2] = body[2] | 128;

                            // Set RCODE to 4
                            body[3] = (body[3] & 240) | 4;

                            // Set RA from 0 to 1
                            body[3] ^= (1 << 7);


                            // Sent back to the client
                            write(i, dns_message.packet_header, 2);
                            write(i, dns_message.packet_body, dns_message.packet_body_size);

                            free_dns_message(&dns_message);
                            close(i);
                            FD_CLR(i, &masterfds);

                        }
                        else {
                            // Check if answer can be found in cache
                            int index = search_in_cache(cache, dns_message.question.QNAME);
                            if(index != -1) {
                                /* Found in cache, go to the packet body, change ID and TTL
                                    also change update the cache time  
                                */
                                uint8_t* ID = cache[index].message.packet_body;
                                // Set ID to match the request
                                ID[0] = dns_message.packet_body[0];
                                ID[1] = dns_message.packet_body[1];

                                
                                uint8_t* TTL_ptr = cache[index].message.answer.TTL;
                                uint32_t time_to_live = read_four_bytes(TTL_ptr);

                                time_t current;
                                time(&current);


                                time_to_live -= (current - cache[index].cache_time);

                                cache[index].cache_time = current;

                                // Storing the updated TTL
                                uint32_t* four_bytes = (void *) TTL_ptr;
                                *four_bytes = htonl(time_to_live);

                                

                                write(i, cache[index].message.packet_header, 2);
                                write(i, cache[index].message.packet_body, cache[index].message.packet_body_size);

                                time_t expire_time = current + time_to_live;

                                get_timestamp(timestamp);
                                fprintf(log, "%s %s expires at ", timestamp, dns_message.question.QNAME);
                                get_specific_timestamp(timestamp, expire_time);
                                fprintf(log, "%s\n", timestamp);

                                if(cache[index].message.header.ANCOUNT && cache[index].message.answer.ATYPE == 28) {
                                    fprintf(log, "%s %s is at %s\n",timestamp, dns_message.question.QNAME , cache[index].message.answer.address);
                                }

                                fflush(log);
                                
                                free_dns_message(&dns_message);
                                close(i);
                                FD_CLR(i, &masterfds);
                            
                            }
                            else {
                                // Cannot find answer in cache, ask upstream
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

                                // Writes to upstream with the DNS request from client
                                write(upstream_sockfd, dns_message.packet_header, 2);
                                write(upstream_sockfd, dns_message.packet_body, dns_message.packet_body_size);

                                // free the memory allocated to dns_request
                                free_dns_message(&dns_message);

                                // Add upstream socket to masterfds
                                FD_SET(upstream_sockfd, &masterfds);
                                // Update maximum
                                if(upstream_sockfd > maxfd) {
                                    maxfd = upstream_sockfd;
                                }

                                // Add a mapping from upstream to client
                                map_upstream_to_client[upstream_sockfd] = i;

                            }


                        }



                    }
                    else if(dns_message.header.QR == 1) {
                        // A response, cache evication, send back to client

                        // Cache the reponse
                        cache_evication(cache, dns_message, log);

                        /*
                        Log <timestamp> <domain_name> is at <IP address>
                        Cache the question and answer
                        */
                        get_timestamp(timestamp);
                        if(dns_message.header.ANCOUNT && dns_message.answer.ATYPE == 28) {
                            fprintf(log, "%s %s is at %s\n",timestamp, dns_message.question.QNAME , dns_message.answer.address);
                            fflush(log);
                        }
                        // Writes back to the client
                        write(map_upstream_to_client[i], dns_message.packet_header, 2);
                        write(map_upstream_to_client[i], dns_message.packet_body, dns_message.packet_body_size);

                        
                        close(i);
                        FD_CLR(i, &masterfds);
                        close(map_upstream_to_client[i]);
                        FD_CLR(map_upstream_to_client[i], &masterfds);

                    }
                    else {
                        fprintf(stderr, "Wrong QR type\n");
                    }

                }
            }
        }
     
    }
    close(listen_sockfd);
    fclose(log);
    return 0;
}



void get_timestamp(char* timestamp) {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(timestamp, TIMESTAMP_LENGTH + 1, "%FT%T%z", info);
}

void get_specific_timestamp(char* timestamp, time_t time) {
    struct tm *info;
    info = localtime(&time);
    strftime(timestamp, TIMESTAMP_LENGTH + 1, "%FT%T%z", info);
}

void cache_evication(cache_entry_t* cache, dns_message_t message, FILE* log) {
    time_t current;
    time(&current);
    char timestamp[TIMESTAMP_LENGTH + 1];
    get_specific_timestamp(timestamp, current);

    for(int i = 0; i < NUM_OF_CACHE_ENTRY; i++) {
        
        if(is_answer_expired(cache[i])) {
            
            // free the space allocated
            if(cache[i].cache_time != 0) {
                fprintf(log, "%s replacing %s by %s\n", timestamp, 
                cache[i].message.question.QNAME, message.question.QNAME);
                fflush(log);
                free_dns_message(&(cache[i].message));
            }
            
            // Store the current message in cache
            cache[i].message = message;
            cache[i].cache_time = current;

            
            
            

            return;
        }
        
    }
    fprintf(log, "%s replacing %s by %s\n", timestamp, 
    cache[0].message.question.QNAME, message.question.QNAME);
    fflush(log);
    // If all are not expired
    // Evicate the first entry in cache
    free_dns_message(&(cache[0].message)); 
    cache[0].message = message;
    cache[0].cache_time = current;
}


// Check if an answer has expired
bool is_answer_expired(cache_entry_t entry) {
    // If the message is a NULL pointer
    if(!entry.cache_time) {
        return true;
    }
    time_t current;
    time(&current);
    uint32_t time_to_live = read_four_bytes(entry.message.answer.TTL);
    // printf("%d\n",time_to_live);
    // printf("%d\n", (current - entry.cache_time) <= time_to_live);

    return (current - entry.cache_time) > time_to_live;
}

uint32_t read_four_bytes(uint8_t* start) {
    uint32_t* four_bytes = (void*) start;
    return ntohl(*four_bytes);
}

// Seach in the cache to see if we can find same question
// Return -1 if not found
int search_in_cache(cache_entry_t* cache, char* QNAME) {
    for(int i = 0; i < NUM_OF_CACHE_ENTRY; i++) {
        if(!is_answer_expired(cache[i]) && !strcmp(QNAME, cache[i].message.question.QNAME)) {
            return i;
        }
    }
    // printf("%s not found in cache\n", QNAME);
    return -1;
}


