#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <sysexits.h>
    #define SOCKET_T int
    #define SOCKLEN_T socklen_t
    #define MY_EX_USAGE EX_USAGE
    #define StartUDP()
    #define INVALID_SOCKET (-1)
#else
    #include <winsock2.h>
    #include <process.h>
    #define SOCKET_T SOCKET
    #define SOCKLEN_T int
    #define MY_EX_USAGE 2
    #define StartUDP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }
#endif

#include <event2/event.h>


/* datagram msg size */
#define MSG_SIZE 20000 
#define pkt_number 10000
struct event_base* base;               /* main base */
struct sockaddr_in proxy, server;      /* proxy address and server address */
int serverLen = sizeof(server);        /* server address len */
int dropPacket    = 0;                 /* dropping packet interval */
int delayPacket   = 0;                 /* delay packet interval */
int dropSpecific  = 0;                 /* specific seq to drop in epoch 0 */
int dropSpecificSeq  = 0;              /* specific seq to drop in epoch 0 */
int delayByOne    = 0;                 /* delay packet by 1 */
int dupePackets   = 0;                 /* duplicate all packets */
int retxPacket = 0;                    /* specific seq to retransmit */
int injectAlert = 0;                   /* inject an alert at end of epoch 0 */
const char* selectedSide = NULL;       /* Forced side to use */
struct event* dlyEvent;
struct timeval dlytimeval;
typedef struct proxy_ctx {
    SOCKET_T  clientFd;       /* from client to proxy, downstream */
    SOCKET_T  serverFd;       /* form server to proxy, upstream   */
} proxy_ctx;


typedef struct delay_packet {
    char           msg[MSG_SIZE];   /* msg to delay */
    int            msgLen;          /* msg size */
    double        storeTime;       /* msg count for when to stop the delay */
    double        delayTime;       /* msg count for when to stop the delay */
    int           dropProb;
    SOCKET_T       peerFd;          /* fd to later send on */
    proxy_ctx*     ctx;             /* associated context */
} delay_packet;

delay_packet  tmpDelay[pkt_number];            /* our tmp holder */
delay_packet* currDelay[pkt_number];    /* current packet to delay */


static char* serverSide = "server";
static char* clientSide = "client";


int   myoptind;
char* myoptarg;


static int GetOpt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}


static char* GetRecordType(const char* msg)
{
    if (msg[0] == 0x16) {
        if (msg[13] == 0x01)
            return "Client Hello";
        else if (msg[13] == 0x00)
            return "Hello Request";
        else if (msg[13] == 0x03)
            return "Hello Verify Request";
        else if (msg[13] == 0x04)
            return "Session Ticket";
        else if (msg[13] == 0x0b)
            return "Certificate";
        else if (msg[13] == 0x0d)
            return "Certificate Request";
        else if (msg[13] == 0x0f)
            return "Certificate Verify";
        else if (msg[13] == 0x02)
            return "Server Hello";
        else if (msg[13] == 0x0e)
            return "Server Hello Done";
        else if (msg[13] == 0x10)
            return "Client Key Exchange";
        else if (msg[13] == 0x0c)
            return "Server Key Exchange";
        else
            return "Encrypted Handshake Message";
    }
    else if (msg[0] == 0x14)
        return "Change Cipher Spec";
    else if (msg[0] == 0x17)
        return "Application Data";
    else if (msg[0] == 0x15)
        return "Alert";

    return "Unknown";
}
void currDelay_init(){
    for(int i=0;i<pkt_number;i++){
        currDelay[i] = NULL;
    }
}

double get_time (void)
{
    long            ms; // Milliseconds
    time_t          s;  // Seconds
    struct timespec spec;
    double combine;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        s++;
        ms = 0;
    }
    combine = (double)s + (double)ms/1000;

    //printf("%f\n", combine);
    return combine;
}
double get_ms (void)
{
    double            ms; // Milliseconds
    time_t          s;
    struct timeval spec;
    double combine;
    //clock_gettime(CLOCK_REALTIME, &spec);
    gettimeofday(&spec,NULL);
    //printf("%ld\n",spec.tv_usec);
    s  = spec.tv_sec;
    ms = (double)spec.tv_usec / 1.0e6; // Convert nanoseconds to milliseconds

    combine = (double)s + (double)ms;

    //printf("%f\n", combine);
    return combine;
}
static void dly(evutil_socket_t fd, short which, void* arg)
{
    //printf("%f\n", get_time());
    static int sendCount = 0;
    if(delayPacket == -1 && dropPacket == -1){
        for(int i = 0; i < pkt_number; i++){
            if(currDelay[i] != NULL){
                if(get_ms()-currDelay[i]->storeTime >= currDelay[i]->delayTime/1000){
                    //printf("%d %f,%d\n",i,currDelay[i]->delayTime,currDelay[i]->dropProb);
                    if(((rand() % 100) + 1)  > currDelay[i]->dropProb){
                        send(currDelay[i]->peerFd, currDelay[i]->msg, currDelay[i]->msgLen, 0);
                        currDelay[i] = NULL;
                        
                    }
                    else{
                        currDelay[i] = NULL;
                        //printf("no\n");
                    }
                
                }    
            }

        }
    }
    else{
        if (delayPacket != 0 && currDelay[sendCount+1] != NULL) {  
            if(get_ms()-currDelay[sendCount+1]->storeTime >= (double)delayPacket/1000){
                send(currDelay[sendCount+1]->peerFd, currDelay[sendCount+1]->msg, currDelay[sendCount+1]->msgLen, 0);
                currDelay[sendCount+1] = NULL;
                sendCount++;
                printf("*** sending on delayed packet\n");
                if(sendCount == (pkt_number - 1)){
                    sendCount = 0;
                }
            }         
        }
    }
    //printf("%f\n",get_ms());
    dlytimeval.tv_sec = 0;
    dlytimeval.tv_usec = 0.01;
    event_add(dlyEvent, &dlytimeval);
}

/* msg callback, send along to peer or do manipulation */
/*
static void Msg(evutil_socket_t fd, short which, void* arg)
{
    static int msgCount = 0;
    static int dropNumber = 0;
    int random = 0;
    int specificindex = 0;
    bool findempty = false;
    char       msg[MSG_SIZE];
    proxy_ctx* ctx = (proxy_ctx*)arg;
    int        ret = recv(fd, msg, MSG_SIZE, 0);

    if (ret == 0)
        printf("read 0\n");
    else if (ret < 0)
        printf("read < 0\n");
    else {
        SOCKET_T peerFd;
        char* side;   

        if (ctx->serverFd == fd) {
            peerFd = ctx->clientFd;
            side   = serverSide;
        }
        else {
            peerFd = ctx->serverFd;
            side   = clientSide;
        }

        printf("got %s from %s size %d\n", GetRecordType(msg), side, ret);
        msgCount++;
        if(delayPacket == -1 && dropPacket == -1){
            for(int i = 0; i < pkt_number; i++){
                if(currDelay[i] == NULL){
                    findempty = true;
                    specificindex = i;
                    break;
                }    
            }
            if(findempty == true){
                currDelay[specificindex] = &tmpDelay[specificindex];
                memcpy(currDelay[specificindex]->msg, msg, ret);
                currDelay[specificindex]->msgLen = ret;
                currDelay[specificindex]->peerFd = peerFd;
                currDelay[specificindex]->ctx = ctx;
                currDelay[specificindex]->storeTime = get_time();
                random = ((int)get_ms() % 9) + 1;
                //printf("%d\n",random);
                if(random <= 3){
                    currDelay[specificindex]->delayTime =  100;
                    currDelay[specificindex]->dropProb = 5;   
                }
                else if(random > 6){
                    currDelay[specificindex]->delayTime =  1000;
                    currDelay[specificindex]->dropProb = 20;
                }
                else{
                    currDelay[specificindex]->delayTime =  500;
                    currDelay[specificindex]->dropProb = 10;
                }
                return;
            }
            else{
                printf("*** queue is exhaust\n");
                assert(0);
            }
        }
        else {
            if (delayPacket == 0 && dropPacket != 0 && (msgCount % dropPacket) == 0) {
                printf("*** but dropping this packet\n");
                return;
            }
            if (delayPacket != 0 && peerFd == ctx->serverFd) {
                
                if(dropPacket == 0){
                    if (currDelay[msgCount] == NULL)
                        currDelay[msgCount] = &tmpDelay[msgCount];
                    else {
                        printf("*** oops, still have a packet in delay\n");
                        assert(0);
                    }
                    memcpy(currDelay[msgCount]->msg, msg, ret);
                    currDelay[msgCount]->msgLen = ret;
                    currDelay[msgCount]->peerFd = peerFd;
                    currDelay[msgCount]->ctx = ctx;
                    currDelay[msgCount]->storeTime = get_time();
                    if(msgCount == (pkt_number - 1)){
                        msgCount = 0;
                    }
                    return;            
                }
                else{
                    if((msgCount % dropPacket) == 0){
                        dropNumber++;
                        return;
                    }
                    else{
                        if (currDelay[msgCount-dropNumber] == NULL)
                            currDelay[msgCount-dropNumber] = &tmpDelay[msgCount-dropNumber];
                        else {
                            printf("*** oops, still have a packet in delay\n");
                            assert(0);
                        }
                        memcpy(currDelay[msgCount-dropNumber]->msg, msg, ret);
                        currDelay[msgCount-dropNumber]->msgLen = ret;
                        currDelay[msgCount-dropNumber]->peerFd = peerFd;
                        currDelay[msgCount-dropNumber]->ctx = ctx;
                        currDelay[msgCount-dropNumber]->storeTime = get_time();
                        if((msgCount-dropNumber) == (pkt_number - 1)){
                            msgCount = 0;
                            dropNumber = 0;
                        }

                        return;                    
                    }
                }
            }
            send(peerFd, msg, ret, 0);
        }
    }
}
*/

/* new client callback */
static void newClient(evutil_socket_t fd, short which, void* arg)
{
    //int ret, on = 1;
    struct sockaddr_in client;
    SOCKLEN_T len = sizeof(client);
    char msg[MSG_SIZE];
    int  msgLen;
    //struct event* cliEvent;
    //struct event* srvEvent;

    //evutil_socket_t dlyFd = 0;

    static int msgCount = 0;
    static int dropNumber = 0;
    static bool gotfirst = false;
    int random = 0;
    int specificindex = 0;
    bool findempty = false;
    static SOCKET_T serverFd;

    struct timeval time; 
    gettimeofday(&time,NULL);
    srand(time.tv_usec);

    proxy_ctx* ctx = (proxy_ctx*)malloc(sizeof(proxy_ctx));
    if (ctx == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    /* let's 'connect' to client so main loop doesn't hear about this
       'connection' again, also allows pairing with upStream 'connect' */
    msgLen = recvfrom(fd, msg, MSG_SIZE, 0, (struct sockaddr*) & client, &len);
    //printf("got %s from client, first msg\n", GetRecordType(msg));
    /*
    ctx->clientFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->clientFd == INVALID_SOCKET) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(ctx->clientFd, SOL_SOCKET, SO_REUSEADDR,
        (char*)&on, (SOCKLEN_T)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(ctx->clientFd, SOL_SOCKET, SO_REUSEPORT,
        (char*)&on, (SOCKLEN_T)sizeof(on));
#endif
    
    ret = bind(ctx->clientFd, (struct sockaddr*) & proxy, sizeof(proxy));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    ret = connect(ctx->clientFd, (struct sockaddr*) & client, len);
    if (ret < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }
    */
    if (gotfirst == false) {
        //printf("00000000000000000\n");
        serverFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (serverFd < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }
        connect(serverFd, (struct sockaddr*) & server, sizeof(server));
    }
    
    
    if (delayPacket != 0 && gotfirst == false) {
        dlyEvent = event_new(base, fd, EV_TIMEOUT | EV_READ, dly, NULL);
        if (dlyEvent == NULL) {
            perror("event_new failed for dlyEvent");
            exit(EXIT_FAILURE);
        }    
        dlytimeval.tv_sec = 0;
        dlytimeval.tv_usec = 0.01;
        event_add(dlyEvent, &dlytimeval);
    }

    if (msgLen == 0)
        printf("read 0\n");
    else if (msgLen < 0)
        printf("read < 0\n");
    else {
        SOCKET_T peerFd;
        char* side;   /* from message side */

        if (ctx->serverFd == fd) {
            peerFd = ctx->clientFd;
            side = serverSide;
        }
        else {
            peerFd = serverFd;
            side = clientSide;
        }

        gotfirst = true;
        printf("got %s from %s size %d\n", GetRecordType(msg), side, msgLen);
        msgCount++;
        if (delayPacket == -1 && dropPacket == -1) {
            for (int i = 0; i < pkt_number; i++) {
                if (currDelay[i] == NULL) {
                    findempty = true;
                    specificindex = i;
                    break;
                }
            }
            if (findempty == true) {
                currDelay[specificindex] = &tmpDelay[specificindex];
                memcpy(currDelay[specificindex]->msg, msg, msgLen);
                currDelay[specificindex]->msgLen = msgLen;
                currDelay[specificindex]->peerFd = peerFd;
                currDelay[specificindex]->ctx = ctx;
                currDelay[specificindex]->storeTime = get_ms();
                random = (rand() % 9) + 1;
                //printf("%d\n", random);
                if (random <= 3) {
                    currDelay[specificindex]->delayTime = 100;
                    currDelay[specificindex]->dropProb = 5;
                }
                else if (random > 6) {
                    currDelay[specificindex]->delayTime = 1000;
                    currDelay[specificindex]->dropProb = 20;
                }
                else {
                    currDelay[specificindex]->delayTime = 500;
                    currDelay[specificindex]->dropProb = 10;
                }
                return;
            }
            else {
                printf("*** queue is exhaust\n");
                assert(0);
            }
        }
        else {
            if (delayPacket == 0 && dropPacket != 0 && (msgCount % dropPacket) == 0) {
                printf("*** but dropping this packet\n");
                return;
            }
            if (delayPacket != 0 && peerFd == serverFd) {
                if (dropPacket == 0) {
                    if (currDelay[msgCount] == NULL)
                        currDelay[msgCount] = &tmpDelay[msgCount];
                    else {
                        printf("*** oops, still have a packet in delay\n");
                        assert(0);
                    }
                    memcpy(currDelay[msgCount]->msg, msg, msgLen);
                    currDelay[msgCount]->msgLen = msgLen;
                    currDelay[msgCount]->peerFd = peerFd;
                    currDelay[msgCount]->ctx = ctx;
                    currDelay[msgCount]->storeTime = get_ms();
                    printf("*** but delay this packet\n");
                    if (msgCount == (pkt_number - 1)) {
                        msgCount = 0;
                    }
                    return;
                }
                else {
                    if ((msgCount % dropPacket) == 0) {
                        printf("*** but dropping this packet\n");
                        dropNumber++;
                        return;
                    }
                    else {
                        if (currDelay[msgCount - dropNumber] == NULL)
                            currDelay[msgCount - dropNumber] = &tmpDelay[msgCount - dropNumber];
                        else {
                            printf("*** oops, still have a packet in delay\n");
                            assert(0);
                        }
                        memcpy(currDelay[msgCount - dropNumber]->msg, msg, msgLen);
                        currDelay[msgCount - dropNumber]->msgLen = msgLen;
                        currDelay[msgCount - dropNumber]->peerFd = peerFd;
                        currDelay[msgCount - dropNumber]->ctx = ctx;
                        currDelay[msgCount - dropNumber]->storeTime = get_ms();
                        printf("*** but delay this packet\n");
                        if ((msgCount - dropNumber) == (pkt_number - 1)) {
                            msgCount = 0;
                            dropNumber = 0;
                        }

                        return;
                    }
                }
            }

            send(peerFd, msg, msgLen, 0);
        }
    }
    /* client and server both use same Msg relay callback 
    cliEvent = event_new(base, ctx->clientFd, EV_READ | EV_PERSIST, Msg, ctx);
    if (cliEvent == NULL) {
        perror("event_new failed for cliEvent");
        exit(EXIT_FAILURE);
    }
    event_add(cliEvent, NULL);
    */

    /*
    srvEvent = event_new(base, ctx->serverFd, EV_READ|EV_PERSIST, Msg, ctx);
    if (srvEvent == NULL) {
        perror("event_new failed for srvEvent");
        exit(EXIT_FAILURE);
    }
    event_add(srvEvent, NULL);
    */
    /* send along initial client message 
    ret = send(ctx->serverFd, msg, msgLen, 0);
    if (ret < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }*/
}


static void Usage(void)
{
    printf("udp_proxy \n");
    printf("-?                  Help, print this usage\n");
    printf("-p <num>            Proxy port to 'listen' on\n");
    printf("-s <server:port>    Server address in dotted decimal:port\n");
    printf("-d <num>            Drop every <num> packet, default 0\n");
    printf("-y <num>            Delay every packet <num> milliseconds, default 0\n");
}


int main(int argc, char** argv)
{
    SOCKET_T sockfd;
    int ret, ch, on = 1;
    struct event* mainEvent;
    //struct event* dlyEvent;
    //struct timeval dlytimeval;
    short port = -1;
    char* serverString = NULL;

    while ( (ch = GetOpt(argc, argv, "?Dap:s:d:y:x:b:R:S:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);
                break;

            case 'p' :
                port = atoi(myoptarg);
                break;

            case 'd' :
                dropPacket = atoi(myoptarg);
                break;

            case 'y' :
                delayPacket = atoi(myoptarg);
                break;

            case 's' :
                serverString = myoptarg;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
                break;
        }
    }
    currDelay_init();

    if (port == -1) {
        printf("need to set 'listen port'\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    if (serverString == NULL) {
        printf("need to set server address string\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    if (selectedSide == NULL)
        selectedSide = serverSide;

    StartUDP();

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    proxy.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy.sin_port = htons(port);

    memset(&server, 0, sizeof(server));
    ret = evutil_parse_sockaddr_port(serverString, (struct sockaddr*)&server,
                                     &serverLen);
    if (ret < 0) {
        perror("parse_sockaddr_port failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#endif

    ret = bind(sockfd, (struct sockaddr*)&proxy, sizeof(proxy));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    base = event_base_new();
    if (base == NULL) {
        perror("event_base_new failed");
        exit(EXIT_FAILURE);
    }

    mainEvent = event_new(base, sockfd, EV_READ|EV_PERSIST, newClient, NULL);
    if (mainEvent == NULL) {
        perror("event_new failed for mainEvent");
        exit(EXIT_FAILURE);
    }
    event_add(mainEvent, NULL);

    event_base_dispatch(base);

    printf("done with dispatching\n");

    return 0;
}
