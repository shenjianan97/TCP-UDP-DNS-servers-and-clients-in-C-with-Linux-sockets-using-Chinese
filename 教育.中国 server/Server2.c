#include "Server2.h"

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

int main(int argc, char *argv[]) {
    int sock, sock2;
    struct sockaddr_in echoServAddr;
    struct sockaddr_in echoClntAddr;
    unsigned int cliAddrLen;
    unsigned short echoServPort;
    int recvMsgSize;

    unsigned char echoBuffer[ECHOMAX];

    echoServPort = 53;

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        printf("socket() failed.\n");

    memset(&echoServAddr, 0, sizeof(echoServAddr));
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = inet_addr("127.1.1.4");//ip
    echoServAddr.sin_port = htons(echoServPort);

    if ((bind(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr))) < 0)
        printf("bind() failed.\n");


    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;

    struct sockaddr_in a;

    struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    struct R_DATA *ardata = NULL;

    struct TAG tag;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries

//   dns = (struct DNS_HEADER *)&buf;
//
//   dns->id = (unsigned short) htons(getpid());
//   dns->tag = htons(tagInt);
//   dns->q_count = htons(1); //we have only 1 question
//   dns->ans_count = htons(1);
//   dns->auth_count = 0;
//   dns->add_count = 0;

    for (;;) {
        printf("wating!\n");
        cliAddrLen = sizeof(echoClntAddr);

        if ((recvMsgSize = recvfrom(sock, echoBuffer, ECHOMAX, 0, (struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0)
            printf("recvfrom() failed.\n");

        printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));

        uint8_t **p0;

        unsigned char *movingPointer0 = echoBuffer;

        p0 = &movingPointer0;

        struct DNS_HEADER dns_h = getDNSHeader(p0);

        struct QUERY q0 = getQuerySection(p0);

        printf("name: %s\n", q0.name);
        printf("type: %u\n", q0.ques->qtype);
        printf("class: %u\n", q0.ques->qclass);


        char buffer_T[100], buffer_S[100];

        char *TLD = getTLD(q0.name, buffer_T);//find the top level domain

        int dotsNum = getDotsnum(q0.name);//get the number of dots


        if (dotsNum == 2) {//if the query has the next level, education.china
            if (q0.ques->qtype == 1) {//type A
                char *stype = "A";
                //char *SLD=getSLD(q0.name,buffer_S);

                FILE *fp;
                char *buf1, *buf2,*filename, *line;
                int ttl;
                filename = "education.txt";
                if ((fp = fopen(filename, "r")) == NULL) {
                    printf("open file error!!\n");
                    return 0;
                }
                buf1 = (char *) malloc(LINE * sizeof(char));
                buf2 = (char *) malloc(LINE * sizeof(char));
                char address[100];
                memset(address, 0, sizeof(address));
                while (1) {
                    line = ReadData(fp, buf1);
                    strcpy(buf2,buf1);
                    if (!line)
                        break;
                    if (findAnswer(buf1, stype, q0.name, address) == 1) {//address ->ip->addtional rdata
                        sscanf(buf2,"%*s%*s%*s%d",&ttl);
                        break;
                    }
                }

                if (strlen(address) == 0) {
                    printf("Can not find!\n");
                    uint8_t **p;//put the message to the buffer

                    unsigned char* movingPointer = buf;

                    p = &movingPointer;

                    uint8_t *initPointer = buf;

                    put2bytes(p, dns_h.id);
                    //put2bytes(p,tagInt);
                    put2bytes(p, generateDnsFlag(1, dns_h.opcode, 0, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z, 3));
                    put2bytes(p, 1);
                    put2bytes(p, 0);
                    put2bytes(p, 0);
                    put2bytes(p, 0);

                    //query
                    printf("response query name: %s\n", q0.name);
                    changetoDnsNameFormatNew(p, q0.name);
                    //printf("response query name: %s\n",q0.name);
                    put2bytes(p, q0.ques->qtype);
                    printf("type: %u\n", q0.ques->qtype);
                    put2bytes(p, q0.ques->qclass);
                    printf("class: %u\n", q0.ques->qclass);

                    if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr))) != recvMsgSize)
                        printf("sendto() sent a different number of bytes than expected.\n");
                    fclose(fp);
                    continue;


                } else {
                    printf("The address is %s\n", address);
                }
                fclose(fp);

                uint8_t **p;//put the message to the buffer

                unsigned char *movingPointer = buf;

                p = &movingPointer;

                uint8_t *initPointer = buf;

                put2bytes(p, dns_h.id);
                //put2bytes(p,tagInt);
                put2bytes(p, generateDnsFlag(1, dns_h.opcode, 1, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z,
                                             dns_h.rcode));
                put2bytes(p, 1);
                put2bytes(p, 1);
                put2bytes(p, 0);
                put2bytes(p, 0);

                //query
                printf("response query name: %s\n", q0.name);
                changetoDnsNameFormatNew(p, q0.name);
                //printf("response query name: %s\n",q0.name);
                put2bytes(p, q0.ques->qtype);
                printf("type: %u\n", q0.ques->qtype);
                put2bytes(p, q0.ques->qclass);
                printf("class: %u\n", q0.ques->qclass);


                //answer
                struct DNS_RR_A answer;
                //unsigned char domainname[100] = "邮件.北邮.美国";
                answer.name = q0.name;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);

                //change the ip to int type
                int addr0 = nextIP(address, 1);
                int addr1 = nextIP(address, 2);
                int addr2 = nextIP(address, 3);
                int addr3 = nextIP(address, 4);

                answer.addr[0] = addr0;
                answer.addr[1] = addr1;
                answer.addr[2] = addr2;
                answer.addr[3] = addr3;

                //additional.name = domainname;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);
                answer.type = T_A;
                answer.class = 1;
                answer.ttl = ttl;
                answer.data_len = 4;

                encodeRR_A(p, &answer);

                if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *) &echoClntAddr,
                            sizeof(echoClntAddr))) != recvMsgSize)
                    printf("sendto() sent a different number of bytes than expected.\n");
            } else if (q0.ques->qtype == 5) {//type CNAME
                char *stype = "CNAME";
                //char *SLD=getSLD(q0.name,buffer_S);

                FILE *fp;
                char *buf1,*buf2, *filename, *line;
                int ttl;
                filename = "education.txt";
                if ((fp = fopen(filename, "r")) == NULL) {
                    printf("open file error!!\n");
                    return 0;
                }
                buf1 = (char *) malloc(LINE * sizeof(char));
                buf2= (char *) malloc(LINE * sizeof(char));
                char address[100];
                memset(address, 0, sizeof(address));
                while (1) {
                    line = ReadData(fp, buf1);
                    strcpy(buf2,buf1);
                    if (!line)
                        break;
                    if (findAnswer(buf1, stype, q0.name, address) == 1) {//address ->ip->addtional rdata
                        sscanf(buf2,"%*s%*s%*s%d",&ttl);
                        break;
                    }
                }

                if (strlen(address) == 0) {
                    printf("Can not find!\n");
                    uint8_t **p;//put the message to the buffer

                    unsigned char* movingPointer = buf;

                    p = &movingPointer;

                    uint8_t *initPointer = buf;

                    put2bytes(p, dns_h.id);
                    //put2bytes(p,tagInt);
                    put2bytes(p, generateDnsFlag(1, dns_h.opcode, 0, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z, 3));
                    put2bytes(p, 1);
                    put2bytes(p, 0);
                    put2bytes(p, 0);
                    put2bytes(p, 0);

                    //query
                    printf("response query name: %s\n", q0.name);
                    changetoDnsNameFormatNew(p, q0.name);
                    //printf("response query name: %s\n",q0.name);
                    put2bytes(p, q0.ques->qtype);
                    printf("type: %u\n", q0.ques->qtype);
                    put2bytes(p, q0.ques->qclass);
                    printf("class: %u\n", q0.ques->qclass);

                    if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr))) != recvMsgSize)
                        printf("sendto() sent a different number of bytes than expected.\n");
                    fclose(fp);
                    continue;
                } else {
                    printf("The CNAME is %s\n", address);
                }
                fclose(fp);

                uint8_t **p;//put the message to the buffer

                unsigned char *movingPointer = buf;

                p = &movingPointer;

                uint8_t *initPointer = buf;

                put2bytes(p, dns_h.id);
                //put2bytes(p,tagInt);
                put2bytes(p, generateDnsFlag(1, dns_h.opcode, 1, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z,
                                             dns_h.rcode));
                put2bytes(p, 1);
                put2bytes(p, 1);
                put2bytes(p, 0);
                put2bytes(p, 0);

                //query
                printf("response query name: %s\n", q0.name);
                changetoDnsNameFormatNew(p, q0.name);
                //printf("response query name: %s\n",q0.name);
                put2bytes(p, q0.ques->qtype);
                printf("type: %u\n", q0.ques->qtype);
                put2bytes(p, q0.ques->qclass);
                printf("class: %u\n", q0.ques->qclass);


                //answer
                struct DNS_RR_CNAME answer;
                //unsigned char domainname[100] = "邮件.北邮.美国";
                answer.name = q0.name;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);

                answer.cname = address;

                //additional.name = domainname;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);
                answer.type = T_CNAME;
                answer.class = 1;
                answer.ttl = ttl;
                answer.data_len = 4;

                encodeRR_CNAME(p, &answer);

                if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *) &echoClntAddr,
                            sizeof(echoClntAddr))) != recvMsgSize)
                    printf("sendto() sent a different number of bytes than expected.\n");
            } else if (q0.ques->qtype == 15) {

                char *stype = "MX";
                //char *SLD=getSLD(q0.name,buffer_S);

                FILE *fp;
                char *buf1, *buf2,*filename, *line,*line1;
                int ttl;
                int preference;
                filename = "education.txt";
                if ((fp = fopen(filename, "r")) == NULL) {
                    printf("open file error!!\n");
                    return 0;
                }
                buf1 = (char *) malloc(LINE * sizeof(char));
                buf2=(char *) malloc(LINE * sizeof(char));
                char address[100];
                char addip[100];
                memset(address, 0, sizeof(address));
                memset(addip, 0, sizeof(addip));
                while (1) {

                    line = ReadData(fp, buf1);
                    strcpy(buf2,buf1);
                    if (!line)
                        break;
                   if (findAnswer(buf1, stype, q0.name, address)== 1 ) {//address ->ip->addtional rdata
                       sscanf(buf2,"%*s%*s%*s%d%s%d",&ttl,addip,&preference);
                        break;
                    }
                }
                if (strlen(address) == 0) {
                    printf("Can not find!\n");
                    uint8_t **p;//put the message to the buffer

                    unsigned char* movingPointer = buf;

                    p = &movingPointer;

                    uint8_t *initPointer = buf;

                    put2bytes(p, dns_h.id);
                    //put2bytes(p,tagInt);
                    put2bytes(p, generateDnsFlag(1, dns_h.opcode, 0, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z, 3));
                    put2bytes(p, 1);
                    put2bytes(p, 0);
                    put2bytes(p, 0);
                    put2bytes(p, 0);

                    //query
                    printf("response query name: %s\n", q0.name);
                    changetoDnsNameFormatNew(p, q0.name);
                    //printf("response query name: %s\n",q0.name);
                    put2bytes(p, q0.ques->qtype);
                    printf("type: %u\n", q0.ques->qtype);
                    put2bytes(p, q0.ques->qclass);
                    printf("class: %u\n", q0.ques->qclass);

                    if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr))) != recvMsgSize)
                        printf("sendto() sent a different number of bytes than expected.\n");
                    fclose(fp);
                    continue;
                } else {
                    printf("The exchange is %s\n", address);
                }
                fclose(fp);

                uint8_t **p;//put the message to the buffer

                unsigned char *movingPointer = buf;

                p = &movingPointer;

                uint8_t *initPointer = buf;

                put2bytes(p, dns_h.id);
                //put2bytes(p,tagInt);
                put2bytes(p, generateDnsFlag(1, dns_h.opcode, 1, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z,
                                             dns_h.rcode));
                put2bytes(p, 1);
                put2bytes(p, 1);
                put2bytes(p, 0);
                put2bytes(p, 1);

                //query
                printf("response query name: %s\n", q0.name);
                changetoDnsNameFormatNew(p, q0.name);
                //printf("response query name: %s\n",q0.name);
                put2bytes(p, q0.ques->qtype);
                printf("type: %u\n", q0.ques->qtype);
                put2bytes(p, q0.ques->qclass);
                printf("class: %u\n", q0.ques->qclass);


                //answer
                struct DNS_RR_MX answer;
                //unsigned char domainname[100] = "邮件.北邮.美国";
                answer.name = q0.name;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);
                answer.preference = preference;
                answer.exchange = address;

                //additional.name = domainname;
                printf("Name is %s\n", answer.name);
                printf("address is : %s\n", address);
                answer.type = T_MX;
                answer.class = 1;
                answer.ttl = ttl;
                answer.data_len = 4;

                encodeRR_MX(p, &answer);

                struct DNS_RR_A addtion;
                addtion.name=q0.name;
                addtion.type=T_A;
                addtion.class=1;

                int addr0 = nextIP(addip, 1);
                int addr1 = nextIP(addip, 2);
                int addr2 = nextIP(addip, 3);
                int addr3 = nextIP(addip, 4);

                addtion.addr[0] = addr0;
                addtion.addr[1] = addr1;
                addtion.addr[2] = addr2;
                addtion.addr[3] = addr3;

                addtion.ttl=ttl;

                encodeRR_A(p,&addtion);


                if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *) &echoClntAddr,
                            sizeof(echoClntAddr))) != recvMsgSize)
                    printf("sendto() sent a different number of bytes than expected.\n");
            } else printf("The type is invalid!");

        } else {
            uint8_t **p;//put the message to the buffer

            unsigned char* movingPointer = buf;

            p = &movingPointer;

            uint8_t *initPointer = buf;

            put2bytes(p, dns_h.id);
            //put2bytes(p,tagInt);
            put2bytes(p, generateDnsFlag(1, dns_h.opcode, 0, dns_h.tc, dns_h.rd, dns_h.ra, dns_h.z, 3));
            put2bytes(p, 1);
            put2bytes(p, 0);
            put2bytes(p, 0);
            put2bytes(p, 0);

            //query
            printf("response query name: %s\n", q0.name);
            changetoDnsNameFormatNew(p, q0.name);
            //printf("response query name: %s\n",q0.name);
            put2bytes(p, q0.ques->qtype);
            printf("type: %u\n", q0.ques->qtype);
            put2bytes(p, q0.ques->qclass);
            printf("class: %u\n", q0.ques->qclass);

            if ((sendto(sock, buf, (*p - initPointer), 0, (struct sockaddr *)&echoClntAddr, sizeof(echoClntAddr))) != recvMsgSize)
                printf("sendto() sent a different number of bytes than expected.\n");
            continue;
        }
    }
}

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void changetoDnsNameFormatNew(unsigned char **dnsPointer, unsigned char *buffer)
{
    int lock = 0 , i;
    char host[100];
    strcpy(host, buffer);
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host); i++)
    {
        if(host[i]=='.')
        {
            **dnsPointer = i-lock;
            (*dnsPointer)++;

//            printf("2: host name is :%s\n", host);
//            printf("length is :%d\n", strlen((char*)host));
            for(;lock<i;lock++)
            {
                **dnsPointer=host[lock];
                (*dnsPointer)++;
//                printf("3: host name is :%s\n", host);
//                printf("length is :%d\n", strlen((char*)host));
            }
            lock++; //or lock=i+1;
        }
    }
    **dnsPointer='\0';
    (*dnsPointer)++;
}

void put1byte(uint8_t **p, uint8_t value){
    memcpy(*p, &value, 1);
    *p += 1;
}

void put2bytes(uint8_t **p, uint16_t value){
    uint16_t value1 = htons(value);
    memcpy(*p, &value1, 2);
    *p += 2;
}

void put4bytes(uint8_t **p, uint32_t value) {
    uint32_t value1 = htonl(value);
    memcpy(*p, &value1, 4);
    *p += 4;
}

void encodeIPAddress(uint8_t **p, uint8_t *name) {
    int i;
//    for (i = 0; i < strlen(name); i++) {
//        put1byte(p, name[i]);
//    }
    put1byte(p, name[0]);
    put1byte(p, name[1]);
    put1byte(p, name[2]);
    put1byte(p, name[3]);
}

void bit_set(uint16_t* p_data, unsigned char position, int flag)
{
    assert(p_data);
    assert(position >= 0 && position <=16);

    if(flag == 1)
    {
        *p_data |= (1<<(position-1));
    }
    else if(flag == 0)
    {
        *p_data &= ~(1<<(position-1));
    }
}

uint16_t generateDnsFlag(int qrValue, int opcodeValue, int aaValue, int tcValue, int rdValue, int raValue, int zValue, int rcodeValue) {
    int qrPosition = 15;
    int opcodePosition = 14;
    int aaPosition = 10;
    int tcPosition = 9;
    int rdPosition = 8;
    int raPosition = 7;
    int zPosition = 6;
    int rcodePosition = 3;
    uint16_t qr = qrValue << qrPosition;
    uint16_t opcode = 0;
    switch (opcodeValue) {
        case 0:
            opcode = 0 << (opcodePosition - 3);
            break;
        case 1:
            opcode = 1 << (opcodePosition - 3);
            break;
        case 2:
            opcode = 1 << (opcodePosition - 2);
            break;
    }
    uint16_t aa = aaValue << aaPosition;
    uint16_t tc = tcValue << tcPosition;
    uint16_t rd = rdValue << rdPosition;
    uint16_t ra = raValue << raPosition;
    uint16_t z = 0 << zPosition;
    uint16_t rcode = 0;
    switch (rcodeValue) {
        case 0:
            rcode = 0;
            break;
        case 1:
            rcode = 1;
            break;
        case 2:
            rcode = 1 << (rcodePosition - 2);
            break;
        case 3:
            rcode = 1 + (1 << (rcodePosition - 2));
            break;
        case 4:
            rcode = 1 << (rcodePosition - 1);
            break;
        case 5:
            rcode = (1 << (rcodePosition - 1)) + 1;
            break;
    }
    uint16_t flag = qr + opcode + aa + tc + rd + ra + z + rcode;
    return flag;
}

u_char* Read_Name(unsigned char* name)
{
    int i = 0;
    int j;
    unsigned int p = 0;

    unsigned char *buf = (unsigned char *)malloc(sizeof(unsigned char) * 200);
    strcpy(buf, name);

    //now convert 3www6google3com0 to www.google.com
    for (i = 0;i < (int)strlen(buf);i++)
    {
        p = buf[i];
        //printf("p is %d\n", p);
        for (j = 0;j < p;j++)
        {
            //printf("aaaa");
            //printf("i is %d", i);
            buf[i] = buf[i + 1];
            //printf("aaa");
            i++;
        }
        buf[i] = '.';
    }
    buf[i-1] = '\0'; //remove the last dot
    printf("in Read name function name is: %s\n", buf);
    return buf;
}


u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0] = '\0';

    //read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; //string complete
    if (jumped == 1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for (i = 0;i < (int)strlen((const char*)name);i++)
    {
        p = name[i];
        for (j = 0;j < (int)p;j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; //remove the last dot
    return name;
}

void encodeRR_MX(uint8_t **p, struct DNS_RR_MX *resourceRecord){
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    resourceRecord->data_len = strlen(resourceRecord->exchange) + 4;
    put2bytes(p, resourceRecord->data_len);
    put2bytes(p, resourceRecord->preference);
    changetoDnsNameFormatNew(p,resourceRecord->exchange);
}

void encodeRR_A(uint8_t **p, struct DNS_RR_A *resourceRecord){
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    put2bytes(p, 4);
    //encodeIPAddress(p, resourceRecord->addr);
    put1byte(p, resourceRecord->addr[0]);
    put1byte(p, resourceRecord->addr[1]);
    put1byte(p, resourceRecord->addr[2]);
    put1byte(p, resourceRecord->addr[3]);
}

void encodeRR_CNAME(uint8_t **p, struct DNS_RR_CNAME *resourceRecord){
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    resourceRecord->data_len = strlen(resourceRecord->cname) + 2;
    put2bytes(p, resourceRecord->data_len);
    changetoDnsNameFormatNew(p, resourceRecord->cname);
}

void encodeRR_NS(uint8_t **p, struct DNS_RR_NS *resourceRecord){
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    resourceRecord->data_len = strlen(resourceRecord->nsname) + 2;
    put2bytes(p, resourceRecord->data_len);
    changetoDnsNameFormatNew(p, resourceRecord->nsname);
}

void encodeQuery(uint8_t **p, struct QUERY *query){
    changetoDnsNameFormatNew(p, query->name);
    put2bytes(p, query->ques->qtype);
    put2bytes(p, query->ques->qclass);
}

char *getString(int choose,char string[],char buf[]) {

    int index = getDotsnum(string);

    char *temp = strtok(buf, ".");


    if(index==1){
        if(choose==1){
            return temp;
        }
        else if(choose==2){
            temp=strtok(NULL,".");
            return temp;
        }
    }
    else if(index==2){
        if(choose==1){
            return temp;
        }
        else if(choose==2){
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose=3){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
    }
    else if(index ==3){
        if(choose==1){
            return temp;
        }
        else if(choose==2){
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose==3){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose=4){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
    }
    else if(index ==4){
        if(choose==1){
            return temp;
        }
        else if(choose==2){
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose==3){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose==4){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
        else if(choose==5){
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            temp=strtok(NULL,".");
            return temp;
        }
    }
}


int con(char *str)
{
    int rt=atoi(str);
    return rt;
}

int nextIP(char s[],int index){
    char buf1[100];
    char buf2[100];
    char buf3[100];
    char buf4[100];
    strcpy(buf1,s);
    strcpy(buf2,s);
    strcpy(buf3,s);
    strcpy(buf4,s);


    char *match1=getString(1,s,buf1);
    char *match2=getString(2,s,buf2);
    char *match3=getString(3,s,buf3);
    char *match4=getString(4,s,buf4);

    int i1=con(match1);
    int i2=con(match2);
    int i3=con(match3);
    int i4=con(match4);

    if(index==1){
        return i1;
    }
    else if(index==2){
        return i2;
    }
    else if(index==3){
        return i3;
    }
    else if(index==4){
        return i4;
    }

}

int getDotsnum(char string[]){
    int i;
    int index = 0;
    for (i = 0;i < strlen(string);i++) {

        if (string[i] == '.') {
            index++;
        }
    }

    return index;
}

char *getTLD(char string[],char buf[]){

    strcpy(buf,string);
    char *match = getString(getDotsnum(string) + 1,string,buf);

    return match;
}

char *getSLD(char string[],char buf[]){
    strcpy(buf,string);
    char *match = getString(getDotsnum(string),string,buf);

    return match;
}

char *ReadData(FILE *fp, char *buf) {
    return fgets(buf, LINE, fp);
}

int findAddress(char *buf, char *domainName, char *output) {
    char* token = strtok(buf, " ");
    if(strcmp(token, domainName) == 0){
        token = strtok(NULL, " ");
        strcpy(output, token);
        return 1;
    }else{
        return 0;
    }
}

int findAnswer(char *buf, char *type, char *domainName,char *output) {
    char* token = strtok(buf, " ");
    if(strcmp(token, type) == 0){
        token = strtok(NULL, " ");
        if(strcmp(token, domainName) == 0) {
            token = strtok(NULL, " ");
            strcpy(output, token);
            return 1;
        }
        else
            return 0;
    }else{
        return 0;
    }
}

/*int findAddip(char *buf, char *type,char *domainName, char *output){
    char *token=strtok(buf, " ");
    if(strcmp(type,token)==0){
        token = strtok(NULL, " ");
        if(strcmp(token, domainName) == 0){
            token = strtok(NULL, " ");
            token = strtok(NULL, " ");
            token = strtok(NULL, " ");
            strcpy(output,token);
            return 1;
        }
        else
            return 0;
    }else
        return 0;
}*/


struct DNS_HEADER getDNSHeader(uint8_t **p){
    struct DNS_HEADER header;
    struct DNS_HEADER *dns;
    dns = (struct DNS_HEADER*)(*p);

    header.id = ntohs(dns->id);
    header.rd = dns->rd;
    header.tc = dns->tc;
    header.aa = dns->aa;
    header.opcode = dns->opcode;
    header.qr = dns->qr;
    header.rcode = dns->rcode;
    header.cd = dns->cd;
    header.ad = dns->ad;
    header.z = dns->z;
    header.ra = dns->ra;
    header.q_count = ntohs(dns->q_count);
    header.ans_count = ntohs(dns->ans_count);
    header.auth_count = ntohs(dns->auth_count);
    header.add_count = ntohs(dns->add_count);
    *p = *p + sizeof(struct DNS_HEADER);

    return header;
}

struct QUERY getQuerySection(uint8_t **p){
    struct QUERY q;
    struct QUESTION* readQuestion;
    struct QUESTION* question;
    q.name= (unsigned char*)(*p);
    *p += strlen((const char*)q.name) + 1;
    question = (struct QUESTION*)malloc(sizeof(struct QUESTION));
    memset(question, 0, sizeof(struct QUESTION));
    readQuestion = (struct QUESTION*)*p;
    question->qclass = ntohs(readQuestion->qclass);
    question->qtype = ntohs(readQuestion->qtype);
    q.ques = question;
    q.name = Read_Name(q.name);
    *p = *p + sizeof(struct QUESTION);

    return q;
}

struct DNS_RR_MX getRRMX(uint8_t **p){
    struct DNS_RR_MX rr;
    struct DNS_RR_DATA *data;
    struct MX_ADDITION *addition;
    rr.name = (unsigned char*)(*p);
    *p += strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    *p += 10;
    addition = (struct MX_ADDITION *)*p;
    rr.preference = ntohs(addition->preference);
    *p += 2;
    rr.exchange = *p;
    *p = *p + 1 + strlen((const char *)rr.exchange);
    rr.exchange = Read_Name(rr.exchange);
    
    return rr;
}

struct DNS_RR_A getRRA(uint8_t **p){
    struct DNS_RR_A rr;
    struct DNS_RR_DATA *data;
    struct A_ADDITION *addition;
    rr.name = (unsigned char *)(*p);
    *p = *p +  strlen((const char*)rr.name) + 1;
    printf("name length is %d\n", (int)(strlen((const char*)rr.name) + 1));
    rr.name = Read_Name(rr.name);
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    //printf("data length is %d\n", rr.data_len);
    //*p = *p + sizeof(struct DNS_RR_DATA);
    //printf("size of DNS_RR_DATA is %d\n", sizeof(struct DNS_RR_DATA));
    *p = *p + 10;
    addition = (struct A_ADDITION *)*p;
    rr.addr[0] = addition->addr[0];
    rr.addr[1] = addition->addr[1];
    rr.addr[2] = addition->addr[2];
    rr.addr[3] = addition->addr[3];
    //printf("address is %d.%d.%d.%d\n", rr.addr[0], rr.addr[1], rr.addr[2], rr.addr[3]);
    *p = *p + 4;

    return rr;
}

struct DNS_RR_CNAME getRRCNAME(uint8_t **p){
    struct DNS_RR_CNAME rr;
    struct DNS_RR_DATA *data;
    struct CNAME_ADDITION *addition;
    rr.name = (unsigned char *)(*p);
    *p = *p +  strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    *p = *p + 10;
    //addition = (struct CNAME_ADDITION *)*p;
    rr.cname = *p;
    *p = *p + strlen((const char*)rr.cname) + 1;
    rr.cname = Read_Name(rr.cname);

    return rr;
}
