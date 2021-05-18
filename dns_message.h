#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

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

#define MAX_DOMAIN_LENGTH 253


// DNS header, only store information needed for this project
// 
typedef struct {
    uint16_t ID;
    bool QR;
    uint16_t QDCOUNT, ANCOUNT;
}dns_header_t;

typedef struct {
    char QNAME[MAX_DOMAIN_LENGTH + 1];
    uint16_t QTYPE;
}dns_question_t;

typedef struct {
    // The type of first answer
    uint16_t ATYPE;
    // Points to the address of the first TTL
    uint8_t* TTL;
    // store ipv6
    char address[INET6_ADDRSTRLEN];
}dns_answer_t;

typedef struct {
    dns_header_t header;
    dns_question_t question;
    dns_answer_t answer;
    uint8_t* packet_header;
    uint8_t* packet_body;
    uint16_t packet_body_size;
}dns_message_t;


dns_message_t read_message(int fd);
void free_dns_message(dns_message_t* dns_message);
uint16_t read_two_bytes(uint8_t* start);

#endif