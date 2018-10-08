//
// Created by shenjianan97 on 18-6-3.
//

#ifndef DNS_UDP_SERVER_DNS_UDP_SERVER_H
#define DNS_UDP_SERVER_DNS_UDP_SERVER_H

#include<stdio.h>
#include<unistd.h>
#define ECHOMAX 65500
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid
#include <assert.h>

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

#define LINE 256

struct TAG{
    int qr; //0 for query, 1 for response
    int opcode; //0 for standard query, 1 for inverse query, 2 for server status request
    int aa; //quthoritative answer, 1 for authoritative
    int tc; //truncation, 1 for being truncated
    int rd; //recusion designed, Set to 1 by the resolver to request recursive service by the name server.
    int ra; //Recursion Available. 1-bit field. Set to 1 by name server to indicate recursive query support is available.
    int z; //3-bit field. Reserved for future use. Must be set to 0.
    int rcode; //Response Code. 4-bit field that is set by the name server to identify the status of the query: 0: No error condition. 1: Unable to interpret query due to format error.2: Unable to process due to server failure. 3: Name in query does not exist. 4: Type of query not supported. 5:Query refused for policy reasons.
};

struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1; // recursion desired
    unsigned char tc : 1; // truncated message
    unsigned char aa : 1; // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1; // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1; // checking disabled
    unsigned char ad : 1; // authenticated data
    unsigned char z : 1; // its z! reserved
    unsigned char ra : 1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};

struct DNS_RR_MX{
    unsigned char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    uint16_t preference;
    uint8_t *exchange;
};

struct DNS_RR_A{
    unsigned char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    unsigned char addr[4];
};

struct DNS_RR_CNAME{
    unsigned char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    unsigned char *cname;
};

struct DNS_RR_NS{
    unsigned char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    unsigned char *nsname;
};

struct DNS_RR_DATA{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
};

struct MX_ADDITION{
    uint16_t preference;
    uint8_t *exchange;
};

struct A_ADDITION{
    unsigned char addr[4];
};

struct CNAME_ADDITION{
    unsigned char *cname;
};

struct DNS_RR_PRE{
    unsigned char *name;
    uint16_t type;
};

void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
void changetoDnsNameFormatNew(unsigned char **, unsigned char *);
void put1byte(uint8_t **, uint8_t);
void put2bytes(uint8_t **, uint16_t);
void put4bytes(uint8_t **, uint32_t);
void encodeIPAddress(uint8_t **, uint8_t *);
uint16_t generateDnsFlag(int, int, int, int, int, int, int, int);
unsigned char* Read_Name(unsigned char*);
u_char* ReadName(unsigned char*, unsigned char*, int*);
void encodeRR_MX(uint8_t **, struct DNS_RR_MX *);
void encodeRR_A(uint8_t **, struct DNS_RR_A *);
void encodeRR_CNAME(uint8_t **, struct DNS_RR_CNAME *);
void encodeQuery(uint8_t **, struct QUERY *);
void encodeRR_NS(uint8_t **p, struct DNS_RR_NS *resourceRecord);
char * getString(int choose,char string[],char buf[]);
int getDotsnum(char string[]);
char *getTLD(char string[],char buf[]);
char *ReadData(FILE *fp, char *buf);
int findAddress(char *buf, char *domainName, char *output);
struct DNS_HEADER getDNSHeader(uint8_t **p);
struct QUERY getQuerySection(uint8_t **p);
struct DNS_RR_MX getRRMX(uint8_t **p);
struct DNS_RR_A getRRA(uint8_t **p);
struct DNS_RR_CNAME getRRCNAME(uint8_t **p);
int con(char *str);
int nextIP(char s[],int index);
#endif //DNS_UDP_SERVER_DNS_UDP_SERVER_H
