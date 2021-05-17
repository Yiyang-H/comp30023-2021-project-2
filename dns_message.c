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

#include "dns_message.h"


dns_message_t read_message(int fd);
uint16_t read_two_bytes(uint8_t* start);
void free_dns_message(dns_message_t* dns_message);

// Reads a dns message
dns_message_t read_message(int fd) {
    dns_message_t dns_message;
    dns_header_t dns_header;
    dns_question_t dns_question;
    
    uint8_t *header_buffer = (uint8_t*) malloc(sizeof(uint8_t) * 2);
    assert(header_buffer);

    uint16_t size = 2;
    while(size > 0) {
        size -= read(fd, header_buffer+(2-size), size);
    }

    // The size of the body
    size = read_two_bytes(header_buffer);
    dns_message.packet_body_size = size;
    dns_message.packet_header = header_buffer;

    uint8_t* body_buffer = (uint8_t*) malloc(sizeof(uint8_t) * size);
    assert(body_buffer);

    // Read the body from tcp stream
    while(size > 0) {
        size -= read(fd, body_buffer+(dns_message.packet_body_size-size), size);
    }

    dns_message.packet_body = body_buffer;

    /* 
    Start processing data
    */
    uint8_t* current = body_buffer;
    dns_header.ID = read_two_bytes(current);

    // Now points to the 4th byte
    current += 4;

    dns_header.QDCOUNT = read_two_bytes(current);
    
    // Now points to the 6th byte
    current += 2;
    dns_header.ANCOUNT = read_two_bytes(current);

    // Now points to the 12th byte, start of question section
    current += 6;

    // Read the question and store it in QNAME
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
    // If there is a answer section
    // Read the answer section and store the first one
    if(dns_header.ANCOUNT) {
        dns_answer_t dns_answer;
        // Now points to type
        current += 2;
        dns_answer.ATYPE = read_two_bytes(current);
        
        // Now points to TTL
        current += 4;
        dns_answer.TTL = current;

        // Now points to RDATA
        current += 6;
        if(inet_ntop(AF_INET6, current, dns_answer.address, INET6_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            exit(EXIT_FAILURE);
        }
        dns_message.answer = dns_answer;
    }

    dns_message.header = dns_header;
    dns_message.question = dns_question;
    return dns_message;
}

void free_dns_message(dns_message_t* dns_message) {
    if(dns_message){
        free(dns_message->packet_header);
        free(dns_message->packet_body);
    }
}

uint16_t read_two_bytes(uint8_t* start) {
    uint16_t* two_byte = (void*) start;
    return ntohs(*two_byte);
}
