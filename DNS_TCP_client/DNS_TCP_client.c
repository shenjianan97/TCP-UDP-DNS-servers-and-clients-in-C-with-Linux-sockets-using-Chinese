#include "DNS_TCP_client.h"

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

struct sockaddr_in selfAddr;//server-addr
char *selfIP = "127.0.0.1";

int main(int argc, char *argv[]) {
    unsigned char hostname[100];
	int type;
	int choose;

    //Get the DNS servers from the resolv.conf file
    get_dns_servers();

    //Get the hostname from the terminal
    printf("Enter Hostname to Lookup : ");
    scanf("%s" , hostname);

    //Now get the ip of this hostname , A record
	printf("\nEnter the Type to Lookup : ");
	printf("\n1: A   2: CNAME   3: MX : ");
	scanf("%d", &choose);
	if(choose == 1){
		type = T_A;
	}else if(choose == 2){
		type = T_CNAME;
	}else if(choose == 3){
		type = T_MX;
	}else{
		printf("\nSorry! Your input type is out of range!\n");
		exit(1);
	}

    ngethostbyname(hostname , type);

    return 0;
}

void ngethostbyname(unsigned char *host, int query_type) {
	printf("Enter\n");

	int sockfd;
	int fd;//write the file to new file
	struct sockaddr_in echoServAddr;
	struct sockaddr_in selfAddr;
	unsigned short echoServPort = 53;
	unsigned int fromSize;

	char *servIP = "127.0.0.2";
	char *selfIP = "127.0.0.1";
	//servIP = argv[1];

	char echoBuffer[ECHOMAX];
	int flag;

	sockfd = socket(PF_INET, SOCK_STREAM, 0);

	memset(&echoServAddr, 0, sizeof(echoServAddr));
	echoServAddr.sin_family = AF_INET;
	echoServAddr.sin_addr.s_addr = inet_addr(servIP);
	echoServAddr.sin_port = htons(echoServPort);

	memset(&selfAddr, 0, sizeof(selfAddr));
	selfAddr.sin_family = AF_INET;
	selfAddr.sin_addr.s_addr = inet_addr(selfIP);
	selfAddr.sin_port = htons(53);
	bind(sockfd, (struct sockaddr *)&selfAddr, sizeof(selfAddr));

	unsigned char buf[65536], *qname, *reader;
	int i, j, stop, s;

	struct sockaddr_in a;

	struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	struct DNS_HEADER dnsBuffer;

	struct TAG tag;

	uint8_t **p, **p1;

	unsigned char* movingPointer = &buf[2];
	unsigned char *startPointer = buf;

	p = &movingPointer;
	p1 = &startPointer;

	uint8_t *initPointer = &buf[2];

	//Set the DNS structure to standard queries

	tag.qr = 0; //This is a response
	tag.opcode = 0; //This is a standard query
	tag.aa = 0; //Not Authoritative
	tag.tc = 0; //This message is not truncated
	tag.rd = 0; //Recursion Desired
	tag.ra = 0; //Recursion not available! hey we dont have it (lol)
	tag.z = 0;
	tag.rcode = 0;

	printf("Resolving %s", host);

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers

	put2bytes(p, getpid());
	//put2bytes(p,tagInt);
	put2bytes(p, generateDnsFlag(tag.qr, tag.opcode, tag.aa, tag.tc, tag.rd, tag.ra, tag.z, tag.rcode));
	put2bytes(p, 1);
	put2bytes(p, 0);
	put2bytes(p, 0);
	put2bytes(p, 0);


	changetoDnsNameFormatNew(p, host); //host
//   qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
//
//   qinfo->qtype = htons( T_A ); //type of the query , A , MX , CNAME , NS etc
//   qinfo->qclass = htons(1); //its internet (lol)



	//*p = (uint8_t *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];

	put2bytes(p, query_type);
	put2bytes(p, 1);//query

	uint16_t length = *p - initPointer;

	put2bytes(p1, length);
	if (connect(sockfd, (struct sockaddr *)&echoServAddr, sizeof(echoServAddr)) == 0) {
		printf("\nconnect\n");
	}
	else
		printf("connect failed\n");

	if (send(sockfd, buf, length + 2, 0) > 0) {
		printf("success\n");
	}
	else
		printf("success failed\n");


	printf("\nReceiving answer...");
	printf("\nReceiving answer...");
	printf("\nReceiving answer...");

	if (flag = recv(sockfd, buf, 60000, 0) < 0) {
		printf("recv() failed.\n");
	}

	uint8_t **p0;
	unsigned char* movingPointer0 = &buf[2];

	p0 = &movingPointer0;

	struct DNS_HEADER dns_h = getDNSHeader(p0);

	struct QUERY q0 = getQuerySection(p0);

	printf("\nThe response contains : ");
	printf("\n %d Questions.",dns_h.q_count);
	printf("\n %d Answers.", dns_h.ans_count);
	printf("\n %d Authoritative Servers.", dns_h.auth_count);
	printf("\n %d Additional records.\n\n", dns_h.add_count);

	if(dns_h.ans_count != 0){
		if(dns_h.aa == 1){
				printf("Authoritative answer:\n");
			}else if(dns_h.aa == 0){
				printf("Non authoritative answer:\n");
			}
		if (query_type == 1) {
			struct DNS_RR_A answer = getRRA(p0);
			char ha[100];
			memset(ha, 0, sizeof(ha));
			char finalIP[100];
			memset(finalIP, 0, sizeof(finalIP));

			sprintf(ha, "%d", answer.addr[0]);
			strcat(ha, ".");
			strcat(finalIP, ha);
			sprintf(ha, "%d", answer.addr[1]);
			strcat(ha, ".");
			strcat(finalIP, ha);
			sprintf(ha, "%d", answer.addr[2]);
			strcat(ha, ".");
			strcat(finalIP, ha);
			sprintf(ha, "%d", answer.addr[3]);
			strcat(finalIP, ha);

			printf("The hostname you look up is : %s\n", answer.name);
			printf("TTL: %d\n", answer.ttl);
			printf("Class: %d(IN)\n",answer.class);
			printf("Type: %d(A)\n", answer.type);
			printf("The Host Address is : %s\n", finalIP);
		}
		else if (query_type == 5) {
			struct DNS_RR_CNAME answer = getRRCNAME(p0);

			printf("The hostname you look up is : %s\n",  answer.name);
			printf("TTL: %d\n", answer.ttl);
			printf("Class: %d(IN)\n", answer.class);
			printf("Type: %d(CNAME)\n", answer.type);
			printf("The Canonical Name is : %s\n", answer.cname);
		}
		else {
			struct DNS_RR_MX answer = getRRMX(p0);
			printf("The hostname you look up is : %s\n",  answer.name);
			printf("TTL: %d\n", answer.ttl);
			printf("Class: %d(IN)\n", answer.class);
			printf("Type: %d(MX)\n", answer.type);
			printf("The Mail Exchange is : %s\n", answer.exchange);

			struct DNS_RR_A additional = getRRA(p0);
			printf("IP is %d.%d.%d.%d\n", additional.addr[0], additional.addr[1], additional.addr[2], additional.addr[3]);

		}
	}else{
		printf("Can not find the answer!!!!!\n");
	}
    close(sockfd);

    return;
}


//***********begin of encoding function**************
//********it should be called in right order*********

//void changetoDnsNameFormat(unsigned char **dnsPointer, unsigned char *buffer)
//{
//    int lock = 0 , i;
//    char host[100];
//    strcat((char*)buffer,".");
//
//    for(i = 0 ; i < strlen((char*)host); i++)
//    {
//        if(host[i]=='.')
//        {
//            **dnsPointer = i-lock;
//            (*dnsPointer)++;
//
//            //            printf("2: host name is :%s\n", host);
//            //            printf("length is :%d\n", strlen((char*)host));
//            for(;lock<i;lock++)
//            {
//                **dnsPointer=host[lock];
//                (*dnsPointer)++;
//                //                printf("3: host name is :%s\n", host);
//                //                printf("length is :%d\n", strlen((char*)host));
//            }
//            lock++; //or lock=i+1;
//        }
//    }
//    **dnsPointer='\0';
//    (*dnsPointer)++;
//}

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

/*
 put 4 bytes to buffer
 use memcpy to copy
 */
void put1byte(uint8_t **p, uint8_t value){
    memcpy(*p, &value, 1);
    *p += 1;
}

/*
 put 2 bytes to buffer
 use memcpy to copy
 use htons to change to network order
 */
void put2bytes(uint8_t **p, uint16_t value){
    uint16_t value1 = htons(value);
    memcpy(*p, &value1, 2);
    *p += 2;
}

/*
 put 4 bytes to buffer
 use memcpy to copy
 use htonl to change to network order
 */
void put4bytes(uint8_t **p, uint32_t value) {
    uint32_t value1 = htonl(value);
    memcpy(*p, &value1, 4);
    *p += 4;
}

/*
 encode IP address to buffer
 p is the pointer of the pointer of uint8_t
 name is the noamal name format in char[]
 */
void encodeIPAddress(uint8_t **p, uint8_t *name) {
    put1byte(p, name[0]);
    put1byte(p, name[1]);
    put1byte(p, name[2]);
    put1byte(p, name[3]);
}

/*
 use bit operations to generate a DNS flag
 qrvalue stands for the value of QR in int
 opcodeValue stands for the value of opcode in int
 qrvalue stands for the value of QR in int
 qrvalue stands for the value of QR in int
 qrvalue stands for the value of QR in int
 qrvalue stands for the value of QR in int
 qrvalue stands for the value of QR in int
 qrvalue stands for the value of QR in int
 */
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
    //    printf("%d\n", qr);
    //    printf("%d\n", opcode);
    //    printf("%d\n", aa);
    //    printf("%d\n", tc);
    //    printf("%d\n", rd);
    //    printf("%d\n", ra);
    //    printf("%d\n", z);
    //    printf("%d\n", rcode);
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
    return buf;
}

/*
 encode DNS header to buffer
 use moving pointers
 */
void encodeHeader(uint8_t **p, struct DNS_HEADER *dns_h){
    put2bytes(p,dns_h->id);
    put2bytes(p,generateDnsFlag((int)dns_h->qr, (int)dns_h->opcode, (int)dns_h->aa, (int)dns_h->tc, (int)dns_h->rd, (int)dns_h->ra, (int)dns_h->z, (int)dns_h->rcode));
    //    put2bytes(p,generateDnsFlag(dns_h->qr, dns_h->opcode, dns_h->aa, dns_h->tc, dns_h->rd, dns_h->ra, dns_h->z, dns_h->rcode));
    put2bytes(p,dns_h->q_count);
    put2bytes(p,dns_h->ans_count);
    put2bytes(p,dns_h->auth_count);
    put2bytes(p,dns_h->add_count);
}

/*
 encode rr MX to buffer
 use moving pointers
 */
void encodeRR_MX(uint8_t **p, struct DNS_RR_MX *resourceRecord){
    resourceRecord->class = 1;
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    //data length is dertermained by the lenght of exchange
    resourceRecord->data_len = strlen(resourceRecord->exchange) + 4;
    put2bytes(p, resourceRecord->data_len);
    put2bytes(p, resourceRecord->preference);
    changetoDnsNameFormatNew(p,resourceRecord->exchange);
}

/*
 encode rr A to buffer
 use moving pointers
 */
void encodeRR_A(uint8_t **p, struct DNS_RR_A *resourceRecord){
    resourceRecord->class = 1;
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    //data length is 4
    put2bytes(p, 4);
    put1byte(p, resourceRecord->addr[0]);
    put1byte(p, resourceRecord->addr[1]);
    put1byte(p, resourceRecord->addr[2]);
    put1byte(p, resourceRecord->addr[3]);
    //    printf("address is %d.%d.%d.%d\n", resourceRecord->addr[0], resourceRecord->addr[1], resourceRecord->addr[2], resourceRecord->addr[3]);
}

/*
 encode rr cname to buffer
 use moving pointers
 */
void encodeRR_CNAME(uint8_t **p, struct DNS_RR_CNAME *resourceRecord){
    resourceRecord->class = 1;
    //    changetoDnsNameFormat(p, resourceRecord->name);
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    //data length is dertermained by the lenght of cname
    resourceRecord->data_len = strlen(resourceRecord->cname) + 2;
    //    printf("%s", resourceRecord->cname);
    put2bytes(p, resourceRecord->data_len);
    changetoDnsNameFormatNew(p, resourceRecord->cname);
}

/*
 encode rr NS to buffer
 use moving pointers
 */
void encodeRR_NS(uint8_t **p, struct DNS_RR_NS *resourceRecord){
    resourceRecord->class = 1;
    changetoDnsNameFormatNew(p, resourceRecord->name);
    put2bytes(p, resourceRecord->type);
    put2bytes(p, resourceRecord->class);
    put4bytes(p, resourceRecord->ttl);
    //data length is dertermained by the lenght of nsname
    resourceRecord->data_len = strlen(resourceRecord->nsname) + 2;
    //    printf("%s", resourceRecord->nsname);
    put2bytes(p, resourceRecord->data_len);
    changetoDnsNameFormatNew(p, resourceRecord->nsname);
}

/*
 encodequery section to buffer
 use moving pointers
 */
void encodeQuery(uint8_t **p, struct QUERY *query){
    //change the name format
    changetoDnsNameFormatNew(p, query->name);
    put2bytes(p, query->ques->qtype);
    put2bytes(p, query->ques->qclass);
}


//***********begin of resolving function**************
//********it should be called in right order*********

/*
 find the DNS header if received buffer by moving pointer
 use moving pointers
 */
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
    //moving pointer to the end of DNS header + 1
    *p = *p + sizeof(struct DNS_HEADER);
    
    return header;
}

/*
 get quert section in recieved buffer
 use moving pointers
 */
struct QUERY getQuerySection(uint8_t **p){
    struct QUERY q;
    struct QUESTION* readQuestion;
    struct QUESTION* question;
    q.name= (unsigned char*)(*p);
    *p += strlen((const char*)q.name) + 1;
    //new a question to store struct question
    question = (struct QUESTION*)malloc(sizeof(struct QUESTION));
    memset(question, 0, sizeof(struct QUESTION));
    readQuestion = (struct QUESTION*)*p;
    question->qclass = ntohs(readQuestion->qclass);
    question->qtype = ntohs(readQuestion->qtype);
    q.ques = question;
    //change name format
    q.name = Read_Name(q.name);
    //move pointer to the end of question +1
    *p = *p + sizeof(struct QUESTION);
    
    //*******end of function*******
    //return
    return q;
}

/*
 get type mx of rr in recieved buffer
 use moving pointers
 */
struct DNS_RR_MX getRRMX(uint8_t **p){
    struct DNS_RR_MX rr;
    struct DNS_RR_DATA *data;
    struct MX_ADDITION *addition;
    //change the pointer to unsigned char*
    rr.name = (unsigned char*)(*p);
    //move the pointer to the end of rr name
    *p += strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    //change the type of pointer to truct DNS_RR_DATA *
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    //move pointer by 10
    *p += 10;
    addition = (struct MX_ADDITION *)*p;
    rr.preference = ntohs(addition->preference);
    //move pointer by 2
    *p += 2;
    rr.exchange = *p;
    //move pointer to the end of exchange + 1
    *p = *p + 1 + strlen((const char *)rr.exchange);
    //change name format
    rr.exchange = Read_Name(rr.exchange);
    
    //*******end of function*******
    //return
    return rr;
}

/*
 get type a of rr in recieved buffer
 use moving pointers
 */
struct DNS_RR_A getRRA(uint8_t **p){
    struct DNS_RR_A rr;
    struct DNS_RR_DATA *data;
    struct A_ADDITION *addition;
    //change the pointer to unsigned char*
    rr.name = (unsigned char *)(*p);
    *p = *p +  strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    //change the pointer to struct DNS_RR_DATA *
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    //move pointer by 10
    *p = *p + 10;
    //change the type of pointer to struct A_ADDITION *
    addition = (struct A_ADDITION *)*p;
    rr.addr[0] = addition->addr[0];
    rr.addr[1] = addition->addr[1];
    rr.addr[2] = addition->addr[2];
    rr.addr[3] = addition->addr[3];
    //move pointer by 4
    *p = *p + 4;
    
    //*******end of function*******
    //return
    return rr;
}

/*
 get type cname of rr in recieved buffer
 use moving pointers
 */
struct DNS_RR_CNAME getRRCNAME(uint8_t **p){
    struct DNS_RR_CNAME rr;
    struct DNS_RR_DATA *data;
    struct CNAME_ADDITION *addition;
    rr.name = (unsigned char *)(*p);
    //move pointer to the end of rr name
    *p = *p +  strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    //move pointer by 10
    *p = *p + 10;
    rr.cname = *p;
    *p = *p + strlen((const char*)rr.cname) + 1;
    rr.cname = Read_Name(rr.cname);
    
    //*******end of function*******
    //return
    return rr;
}
