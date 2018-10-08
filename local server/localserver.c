#include "localserver.h"

char dns_servers[10];

//htonl(INADDR_ANY);

struct sockaddr_in selfAddr;//server-addr
char *selfIP = "127.0.0.2";
int udpSocket;
int isrestart = 0;
char *cacheFileName = "cache.txt";

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in echoServAddr;//server-addr
    struct sockaddr_in echoClntAddr;//clientaddre
    //addr-len =sizeof(clientadre)
    unsigned int cliAddrLen;
    unsigned short echoServPort;
    int recvMsgSize;
    unsigned char echoBuffer[ECHOMAX];
    int i;
    int fd, newsockfd;
    char filename[] = "cache.txt";
    i = 0;
    char *servIP = "127.0.0.2";
    //char buf[255];
    unsigned char buf[ECHOMAX];
    unsigned char TCPSendbuf[ECHOMAX];
    memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));

    uint8_t **p, **pp;

    unsigned char *movingPointer = &TCPSendbuf[2];
    unsigned char *startPointer = TCPSendbuf;

    p = &movingPointer;
    pp = &startPointer;

    unsigned char *initPointer = &TCPSendbuf[2];

    echoServPort = 53;
    cliAddrLen = sizeof(echoClntAddr);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&echoServAddr, 0, sizeof(echoServAddr));
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = inet_addr(servIP);
    //htonl(INADDR_ANY);
    echoServAddr.sin_port = htons(echoServPort);

    struct DNS_RR_MX answerMX;
    struct DNS_RR_A answerA;
    struct DNS_RR_CNAME answerCNAME;

    struct DNS_RR_A answerMXadd;

    if(bind(sockfd, (struct sockaddr *)&echoServAddr, sizeof(echoServAddr)) < 0){
        printf("Bind failed!\nPlease wait for a while!\n");
        exit(1);
    }

    listen(sockfd, 5);

    printf("Server started!\n");

    for (;;) {
        printf("\nWaiting for connection...\n");
        newsockfd = accept(sockfd, (struct sockaddr*)&echoClntAddr, &cliAddrLen);
        if (newsockfd > 0) {
            printf("Connected with client %s in port %d\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
        }
        if (recv(newsockfd, echoBuffer, ECHOMAX, 0)) {
            printf("Received a DNS message from client %s in port %d\n\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
            uint8_t **p0;
            unsigned char* movingPointer0 = &echoBuffer[2];

            p0 = &movingPointer0;

            struct DNS_HEADER dns_h = getDNSHeader(p0);

            struct QUERY q0 = getQuerySection(p0);


            printf("***********QUERY SECTION************\n");
            printf("Query name is: %s\n", q0.name);
            char *queryType;
            switch(q0.ques->qtype){
                case T_A:
                    queryType = "T_A";
                    break;
                case T_MX:
                    queryType = "T_MX";
                    break;
                case T_CNAME:
                    queryType = "T_CNAME";
                    break;
                default:
                    queryType = "UNKNOWN";
                    break;
            }
            printf("Query type is: %s\n", queryType);
            printf("Query class is: IN\n");
            printf("********END OF QUERY SECTION********\n\n");

            char buffer_T[100],buffer_S[100];
            char * TLD = getTLD(q0.name, buffer_T);

            //read cache
            FILE *fpReader;
            char *buf1, *filename, *line;
            if ((fpReader = fopen(cacheFileName, "r")) == NULL) {
                printf("open file error!!\n");
                return 0;
            }
            buf1 = (char*)malloc(LINE*sizeof(char));
            memset(buf, 0, LINE*sizeof(char));

            int isFind = 0;
            switch(q0.ques->qtype){
                case T_A:
                    while((line = ReadData(fpReader, buf1))){
                        char buffer[200];
                        memset(buffer, 0 , sizeof(buffer));
                        strcpy(buffer, line);
                        char *token = strtok(buffer, " ");
                        if(strcmp(token, "A") == 0){
                            token = strtok(NULL, " ");
                            if(strcmp(token, q0.name) == 0){
                                printf("Found a resource record in cache!\n");
                                isFind = 1;
                                char *IP;
                                IP = (char*)malloc(sizeof(char)*50);
                                int ttl;
                                sscanf(line, "%*s %*s %d %s", &ttl, IP);
                                //change the ip to int type
                                int addr0 = nextIP(IP,1);
                                int addr1 = nextIP(IP,2);
                                int addr2 = nextIP(IP,3);
                                int addr3 = nextIP(IP,4);

                                answerA.addr[0] = addr0;
                                answerA.addr[1] = addr1;
                                answerA.addr[2] = addr2;
                                answerA.addr[3] = addr3;
                                answerA.ttl = ttl;
                                answerA.name = q0.name;
                                answerA.class = 1;
                                answerA.type = T_A;

                                dns_h.qr = 1;
                                dns_h.ans_count = 1;
                                dns_h.aa = 0;

                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                movingPointer = &TCPSendbuf[2];
                                startPointer = TCPSendbuf;
                                encodeHeader(p, &dns_h);
                                encodeQuery(p, &q0);
                                encodeRR_A(p,&answerA);
                                put2bytes(pp, *p - initPointer);

                                printf("Send the response DNS message back to client %s in port %d\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
                                printf("Answer section: %s A %d %d.%d.%d.%d\n", answerA.name, answerA.ttl, answerA.addr[0], answerA.addr[1], answerA.addr[2], answerA.addr[3]);

                                printf("Sending to client...\n");
                                send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                                printf("Done\n");
                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                close(newsockfd);
                                break;
                            }
                        }
                    }
                    if(isFind == 1){
                        printf("************************************\n");
                        continue;
                    }
                    break;
                case T_MX:
                    while((line = ReadData(fpReader, buf1))){
                        char buffer[200];
                        strcpy(buffer, line);
                        char *token = strtok(buffer, " ");
                        if(strcmp(token, "MX") == 0){
                            token = strtok(NULL, " ");
                            if(strcmp(token, q0.name) == 0){
                                printf("Found a resource record in cache!\n");
                                isFind = 1;
                                char *IP, *exchange;
                                IP = (char*)malloc(sizeof(char)*50);
                                exchange = (char*)malloc(sizeof(char)*100);
                                int ttl;
                                int preference;
                                sscanf(line, "%*s %*s %s %d %d %s", exchange, &preference, &ttl, IP);
                                //change the ip to int type
                                int addr0 = nextIP(IP,1);
                                int addr1 = nextIP(IP,2);
                                int addr2 = nextIP(IP,3);
                                int addr3 = nextIP(IP,4);

                                answerMXadd.addr[0] = addr0;
                                answerMXadd.addr[1] = addr1;
                                answerMXadd.addr[2] = addr2;
                                answerMXadd.addr[3] = addr3;
                                answerMXadd.ttl = ttl;

                                answerMXadd.name = exchange;
                                answerMXadd.class = 1;
                                answerMXadd.type = T_A;

                                answerMX.name = q0.name;
                                answerMX.exchange = exchange;
                                answerMX.preference = preference;
                                answerMX.ttl = answerMXadd.ttl;
                                answerMX.class = 1;
                                answerMX.type = T_MX;



                                dns_h.qr = 1;
                                dns_h.ans_count = 1;
                                dns_h.add_count = 1;
                                dns_h.aa = 0;

                                movingPointer = &TCPSendbuf[2];
                                startPointer = TCPSendbuf;
                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                encodeHeader(p, &dns_h);
                                encodeQuery(p, &q0);
                                encodeRR_MX(p,&answerMX);
                                encodeRR_A(p,&answerMXadd);
                                put2bytes(pp, *p - initPointer);

                                printf("Send the response DNS message back to client %s in port %d\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
                                printf("Answer section: %s MX %d %s\n",  answerMX.name, answerMX.ttl, answerMX.exchange);
                                printf("Additional section: %s A %d %d.%d.%d.%d\n", answerMXadd.name, answerMXadd.ttl, answerMXadd.addr[0], answerMXadd.addr[1], answerMXadd.addr[2], answerMXadd.addr[3]);

                                printf("Sending to client...\n");
                                send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                                printf("Done\n");
                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                close(newsockfd);
                                break;
                            }
                        }
                    }
                    if(isFind == 1){
                        printf("************************************\n");
                        continue;
                    }
                    break;
                case T_CNAME:
                    while((line = ReadData(fpReader, buf1))){
                        char buffer[200];
                        strcpy(buffer, line);
                        char *token = strtok(buffer, " ");
                        if(strcmp(token, "CNAME") == 0){
                            token = strtok(NULL, " ");
                            if(strcmp(token, q0.name) == 0){
                                printf("Found a resource record in cache!\n");
                                isFind = 1;
                                char *exchange;
                                exchange = (char*)malloc(sizeof(char)*100);
                                int ttl;
                                sscanf(line, "%*s %*s %d %s", &ttl, exchange);
                                //change the ip to int type

                                answerCNAME.name = q0.name;
                                answerCNAME.type = T_CNAME;
                                answerCNAME.class = 1;
                                answerCNAME.cname = exchange;
                                answerCNAME.ttl = ttl;

                                dns_h.qr = 1;
                                dns_h.ans_count = 1;
                                dns_h.aa = 0;

                                movingPointer = &TCPSendbuf[2];
                                startPointer = TCPSendbuf;
                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                encodeHeader(p, &dns_h);
                                encodeQuery(p, &q0);
                                encodeRR_CNAME(p,&answerCNAME);
                                put2bytes(pp, *p - initPointer);

                                printf("Send the response DNS message back to client %s in port %d\n", inet_ntoa(echoClntAddr.sin_addr), ntohs(echoClntAddr.sin_port));
                                printf("Answer section: %s CNAME %d %s\n", answerCNAME.name, answerCNAME.ttl, answerCNAME.cname);

                                printf("Sending to client...\n");
                                send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                                printf("Done!");
                                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                                close(newsockfd);
                                break;
                            }
                        }
                    }
                    if(isFind == 1){
                        printf("************************************\n");
                        continue;
                    }
                    break;
            }

            printf("Can not find the answer in local cache!\nStart to do iteration query!\n");
            //send the iteration query
            unsigned char * receiveBuffer = ngethostbyname(q0.name,q0.ques->qtype,dns_h.id);

            //start to resolve the answer
            uint8_t **p1;

            unsigned char* movingPointer1 = receiveBuffer;

            p1 = &movingPointer1;

            struct DNS_HEADER header = getDNSHeader(p1);

            struct QUERY query = getQuerySection(p1);

            if(header.rcode == 3 || header.ans_count == 0){
                movingPointer = &TCPSendbuf[2];
                startPointer = TCPSendbuf;
                memset(TCPSendbuf, 0, sizeof(TCPSendbuf));
                encodeHeader(p, &header);
                encodeQuery(p, &query);
                put2bytes(pp, *p - initPointer);
                printf("Sending to client...\n");
                send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                printf("Done!\n");
                memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                printf("************************************\n");
                continue;
            }

            FILE *fpWriter;
            if ((fpWriter = fopen(cacheFileName, "a+")) == NULL) {
                printf("open file error!!\n");
                return 0;
            }
            fseek(fpWriter, 0, SEEK_END);

            switch(query.ques->qtype){
                case T_A:
                    answerA = getRRA(p1);

                    //write cache
                    printf("writing cache!!!!!!\n");
                    int a;
                    if(fprintf(fpWriter, "A %s %d %d.%d.%d.%d\n", query.name, answerA.ttl, answerA.addr[0], answerA.addr[1], answerA.addr[2], answerA.addr[3]) == -1){
                        printf("writing error!!!!!!!!!!!!!!!!!!");
                    }
                    movingPointer = &TCPSendbuf[2];
                    startPointer = TCPSendbuf;
                    memset(TCPSendbuf, 0, sizeof(TCPSendbuf));
                    encodeHeader(p, &header);
                    encodeQuery(p, &query);
                    encodeRR_A(p, &answerA);
                    put2bytes(pp, *p - initPointer);
                    printf("Sending to client...\n");
                    send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                    printf("Done!\n");
                    memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                    fclose(fpWriter);
                    printf("************************************\n");
                    break;
                case T_MX:
                    answerMX = getRRMX(p1);
                    answerMXadd = getRRA(p1);
                    printf("writing cache!!!!!!\n");
                    if(fprintf(fpWriter, "MX %s %s %d %d %d.%d.%d.%d\n", query.name, answerMX.exchange, answerMX.preference, answerMX.ttl, answerMXadd.addr[0], answerMXadd.addr[1], answerMXadd.addr[2], answerMXadd.addr[3]) == -1){
                        printf("writing error!!!!!!!!!!!!!!!!!!");
                    }
                    movingPointer = &TCPSendbuf[2];
                    startPointer = TCPSendbuf;
                    memset(TCPSendbuf, 0, sizeof(TCPSendbuf));
                    encodeHeader(p, &header);
                    encodeQuery(p, &query);
                    encodeRR_MX(p, &answerMX);
                    encodeRR_A(p, &answerMXadd);
                    put2bytes(pp, *p - initPointer);
                    printf("Sending to client...\n");
                    send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                    printf("Done!\n");
                    memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                    fclose(fpWriter);
                    printf("************************************\n");
                    break;
                case T_CNAME:
                    answerCNAME = getRRCNAME(p1);
                    printf("writing cache!!!!!!\n");
                    if(fprintf(fpWriter, "CNAME %s %d %s\n", query.name, answerCNAME.ttl, answerCNAME.cname) == -1){
                        printf("writing error!!!!!!!!!!!!!!!!!!");
                    }
                    movingPointer = &TCPSendbuf[2];
                    startPointer = TCPSendbuf;
                    memset(TCPSendbuf, 0, sizeof(TCPSendbuf));
                    encodeHeader(p, &header);
                    encodeQuery(p, &query);
                    encodeRR_CNAME(p, &answerCNAME);
                    put2bytes(pp, *p - initPointer);
                    printf("Sending to client...\n");
                    send(newsockfd, TCPSendbuf, (*p - initPointer + 2), 0);
                    printf("Done!\n");
                    memset(TCPSendbuf, 0 , sizeof(TCPSendbuf));
                    fclose(fpWriter);
                    printf("************************************\n");
                    break;
            }
            close(newsockfd);
        }
    }
}

unsigned char *ngethostbyname(unsigned char *host , int query_type, uint16_t transactionID)
{
    unsigned char *buf, *echoBuffer,*qname,*reader;
    buf = (unsigned char *)malloc(sizeof(unsigned char) * ECHOMAX);
    echoBuffer = (unsigned char *)malloc(sizeof(unsigned char) * ECHOMAX);
    int i , j , stop;

    struct sockaddr_in a;

    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    struct DNS_HEADER dnsBuffer;

    struct TAG tag;

    uint8_t **p;

    unsigned char *movingPointer = buf;

    p = &movingPointer;

    uint8_t *initPointer = buf;

    if(isrestart == 0) {
        udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries
    }
    memset(&selfAddr, 0, sizeof(selfAddr));
    selfAddr.sin_family = AF_INET;
    selfAddr.sin_addr.s_addr = inet_addr(selfIP);
    //htonl(INADDR_ANY);
    selfAddr.sin_port = htons(53);
    if(isrestart == 0) {
        if (bind(udpSocket, (struct sockaddr *) &selfAddr, sizeof(selfAddr)) < 0) {
            printf("udp bind failed\n");
        }
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("127.0.0.3"); //dns servers


    //point to the query portion
    tag.qr = 0; //This is a response
    tag.opcode = 0; //This is a standard query
    tag.aa = 0; //Not Authoritative
    tag.tc = 0; //This message is not truncated
    tag.rd = 0; //Recursion Desired
    tag.ra = 0; //Recursion not available! hey we dont have it (lol)
    tag.z = 0;
    tag.rcode = 0;

    put2bytes(p,transactionID);
    //put2bytes(p,tagInt);
    put2bytes(p,generateDnsFlag(tag.qr,tag.opcode,tag.aa,tag.tc,tag.rd,tag.ra,tag.z,tag.rcode));
    put2bytes(p,1); //question count
    put2bytes(p,0); //answer count
    put2bytes(p,0); //authority count
    put2bytes(p,0); //additional count

    //Query section
    qname = host;

    struct QUERY query;
    struct QUESTION question;
    query.name = qname;
    question.qtype = query_type;
    question.qclass = 1;
    query.ques = &question;
    encodeQuery(p, &query);

    printf("Sending Packet to server: 127.0.0.3\n");

    struct timeval starttime1,endtime1;
    gettimeofday(&starttime1,0);

    if( sendto(udpSocket,(char*)buf, (*p - initPointer),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done\n");

    //Receive the answer
    i = sizeof(dest);
    memset(echoBuffer, 0, sizeof(echoBuffer));

    printf("\nReceiving answer...\n");
    if(recvfrom (udpSocket,(char*)echoBuffer, ECHOMAX, 0, (struct sockaddr*)&dest, (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Received a DNS message from %s\n", inet_ntoa(dest.sin_addr));

    gettimeofday(&endtime1,0);
    double timeuse1 = 1000000*(endtime1.tv_sec - starttime1.tv_sec) + endtime1.tv_usec - starttime1.tv_usec;
    timeuse1 /= 1000;
    printf("Time used: %.2lf ms\n", timeuse1);

    uint8_t **p0;

    unsigned char* movingPointer0 = echoBuffer;

    p0 = &movingPointer0;

    struct DNS_HEADER dns_h = getDNSHeader(p0);

    struct QUERY q0 = getQuerySection(p0);

//    printf("name: %s\n", q0.name);
//    printf("type: %u\n", q0.ques->qtype);
//    printf("class: %u\n", q0.ques->qclass);

    char buffer_T[100],buffer_S[100];
    char * TLD = getTLD(q0.name, buffer_T);//find the top level domain

    int dotsNum = getDotsnum(q0.name);//get the number of dots
    if(dns_h.rcode == 3){
        printf("No answer!!!\n");
        isrestart = 1;
        return echoBuffer;
    }
    else if(dns_h.ans_count == 1){
        printf("Found an answer!!!\n");
        isrestart = 1;
        return echoBuffer;
    }
    else{
        printf("Can not find answers!\n");
        printf("Continue doing iteration query!\n\n");
        struct DNS_RR_A add_root = getRRA(p0);
        char topIP[100];
        memset(topIP, 0, sizeof(topIP));

        char finalIP[100];
        memset(finalIP, 0, sizeof(finalIP));

        sprintf(topIP,"%d",add_root.addr[0]);
        strcat(topIP,".");
        strcat(finalIP,topIP);
        sprintf(topIP,"%d",add_root.addr[1]);
        strcat(topIP,".");
        strcat(finalIP,topIP);
        sprintf(topIP,"%d",add_root.addr[2]);
        strcat(topIP,".");
        strcat(finalIP,topIP);
        sprintf(topIP,"%d",add_root.addr[3]);
        strcat(finalIP,topIP);

        char *sip=finalIP;

        //printf("ip:%s\n",sip);
        dest.sin_family = AF_INET;
        dest.sin_port = htons(53);
        dest.sin_addr.s_addr = inet_addr(sip);

        printf("Sending Packet to server: %s\n", inet_ntoa(dest.sin_addr));
        struct timeval starttime2,endtime2;
        gettimeofday(&starttime2, 0);

        if( sendto(udpSocket,(char*)buf, (*p - initPointer),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
        {
            perror("sendto failed");
        }
        printf("Done\n");

        memset(echoBuffer, 0, sizeof(echoBuffer));

        printf("\nReceiving answer...\n");
        if(recvfrom (udpSocket,(char*)echoBuffer , ECHOMAX , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
        {
            perror("recvfrom failed");
        }
        printf("Received a DNS message from %s\n", inet_ntoa(dest.sin_addr));
        gettimeofday(&endtime2, 0);
        double timeuse2 = 1000000*(endtime2.tv_sec - starttime2.tv_sec) + endtime2.tv_usec - starttime2.tv_usec;
        timeuse2 /= 1000;
        printf("Time used: %.2lf ms\n", timeuse2);

        uint8_t **p1;

        unsigned char* movingPointer1 = echoBuffer;

        p1 = &movingPointer1;

        struct DNS_HEADER dns_h1 = getDNSHeader(p1);

        struct QUERY q1=getQuerySection(p1);

//        printf("name: %s\n", q1.name);
//        printf("type: %u\n", q1.ques->qtype);
//        printf("class: %u\n", q1.ques->qclass);
        if(dns_h1.rcode == 3){
            printf("No answer!!!\n");
            isrestart = 1;
            return echoBuffer;
        }
        else if(dns_h1.ans_count==1){
            printf("Found an answer!!!\n");
            isrestart = 1;
            return echoBuffer;
        }
        else {
            printf("Can not find answers!\n");
            printf("Continue doing iteration query!\n");
            struct DNS_RR_A add_root1 = getRRA(p1);
            //int i1=add_root.addr[0];
            //int i2=
            char topIP1[100];
            memset(topIP1, 0, sizeof(topIP1));

            char finalIP1[100];
            memset(finalIP1, 0, sizeof(finalIP1));

            sprintf(topIP1,"%d",add_root1.addr[0]);
            strcat(topIP1,".");
            strcat(finalIP1,topIP1);
            sprintf(topIP1,"%d",add_root1.addr[1]);
            strcat(topIP1,".");
            strcat(finalIP1,topIP1);
            sprintf(topIP1,"%d",add_root1.addr[2]);
            strcat(topIP1,".");
            strcat(finalIP1,topIP1);
            sprintf(topIP1,"%d",add_root1.addr[3]);
            strcat(finalIP1,topIP1);

            char *secondip=finalIP1;

            dest.sin_family = AF_INET;
            dest.sin_port = htons(53);
            dest.sin_addr.s_addr = inet_addr(secondip);

            struct timeval starttime3,endtime3;
            gettimeofday(&starttime3,0);

            printf("Sending Packet to server: %s\n", inet_ntoa(dest.sin_addr));
            if( sendto(udpSocket,(char*)buf, (*p - initPointer),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
            {//send the query to ca or go
                perror("sendto failed");
            }
            printf("Done!\n");

            //memset(buf, 0, sizeof(buf));
            memset(echoBuffer, 0, sizeof(echoBuffer));

            printf("\nReceiving answer...\n");
            if(recvfrom (udpSocket,(char*)echoBuffer , ECHOMAX , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
            {
                perror("recvfrom failed");
            }
            printf("Received a DNS message from %s\n", inet_ntoa(dest.sin_addr));
            gettimeofday(&endtime3,0);
            double timeuse3 = 1000000*(endtime3.tv_sec - starttime3.tv_sec) + endtime3.tv_usec - starttime3.tv_usec;
            timeuse3 /= 1000;

            printf("Time used %.2lf ms\n", timeuse3);

            //receive from the second level domain:jiaoyu or zhengfu
            uint8_t **p2;

            unsigned char* movingPointer2 = echoBuffer;

            p2 = &movingPointer2;

            struct DNS_HEADER dns_h2 = getDNSHeader(p2);

            struct QUERY q2=getQuerySection(p2);

        }
        isrestart = 1;
        return echoBuffer;
    }
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
    *p = *p +  strlen((const char*)rr.name) + 1;
    rr.name = Read_Name(rr.name);
    data = (struct DNS_RR_DATA *)*p;
    rr.type = ntohs(data->type);
    rr.class = ntohs(data->class);
    rr.ttl = ntohl(data->ttl);
    rr.data_len = ntohs(data->data_len);
    *p = *p + 10;
    rr.cname = *p;
    *p = *p + strlen((const char*)rr.cname) + 1;
    rr.cname = Read_Name(rr.cname);

    //*******end of function*******
    //return
    return rr;
}
