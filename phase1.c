/* Phase 1
    Read a raw file and output a text version of it
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
/* Define stdin as the file descripter */
#define FD 0
#define AAAA_TPYE 28

int main(int argc, char** argv) {

    /* Define a buffer of 2 bytes to store a header */
    unsigned char head_buffer[2];
    short *header = (void*) head_buffer;
    int bytes_read = read(FD, head_buffer, 2);
    
    *header = ntohs(*header);

/*     printf("%d\n", bytes_read);
    printf("%d\n", *header);
    printf("\n");
 */
    /* Define a buffer with size given in header */
    unsigned char buffer[*header];
    bytes_read = read(0, buffer, *header);

/*     printf("%d\n", bytes_read);
    for(int i = 0; i < bytes_read; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n"); */

    /* Header of the message */
    short *ID = (void*) buffer;
    *ID = ntohs(*ID);
    bool QR = (buffer[2] >> 7) & 1;

    char opcode = (buffer[2] >> 3) & (16-1);
    bool AA = (buffer[2] >> 2) & 1;
    bool TC = (buffer[2] >> 1) & 1;
    bool RD = buffer[2] & 1;

    // printf("ID: %d, QR: %d, OP: %d, AA: %d, TC: %d, RD: %d\n", *ID, QR, opcode, AA, TC, RD);

    bool RA = (buffer[3] >> 7) & 1;
    char Z = (buffer[3] >> 4) & (8-1);
    char rcode = buffer[3] & (16-1);
    // printf("RA: %d, Z: %d, RCODE: %d\n", RA, Z, rcode);

    short *qdcount = (void*) buffer+4;
    short *ancount = (void*) buffer+6;
    short *nscount = (void*) buffer+8;
    short *arcount = (void*) buffer+10;
    *qdcount = ntohs(*qdcount);
    *ancount = ntohs(*ancount);
    *nscount = ntohs(*nscount);
    *arcount = ntohs(*arcount);
    // printf("QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d\n", *qdcount, *ancount, *nscount, *arcount);
    
    char* time = "2021-04-24T05:12:32+0000 ";
    printf("%s",time);

    /* parse Question section */
    unsigned char* current_byte = buffer+12;
    char qname[255];
    int qname_buddy = 0;
    if(qdcount) {
        /* Loop until length of the label become 0 */
        unsigned char length = *current_byte;
        current_byte += 1;
        while(length) {
            for(;length > 0; length--) {
                
                qname[qname_buddy++] = *current_byte;
                current_byte += 1;
            }
            qname[qname_buddy++] = '.';
            length = *current_byte;
            current_byte += 1;


            /* for(int i = 0; i < length; i++) {
                printf("%d ", label[i]);
            } */
        }
        qname[qname_buddy-1] = '\0';
        
    }
    /* current_byte points to qtype */
    short *qtype = (void*) current_byte;
    *qtype = ntohs(*qtype);


    current_byte += 2;
    short *qclass = (void*) current_byte;
    *qclass = ntohs(*qclass);

    /* printf("qtype: %d, qclass: %d", *qtype, *qclass); */
    if(*qtype == AAAA_TPYE) {
        printf("requested %s\n", qname);
    }else {
        printf("unimplemented request\n");
    }
}