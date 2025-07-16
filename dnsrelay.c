#include <winsock2.h>
#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib, "ws2_32.lib")  //链接 ws2_32.dll
#pragma warning(disable:4996)
#define noneDebug 0
#define oneDebug 1
#define twoDebug 2
#define defaultDNSServer "10.3.9.6"
#define defaultFileName "dnsrelay.txt"
#define ID_TRANS_MAX 2000
#define IP_URL_MAX 500
#define DNSSERVER_NO_REPLY 20
#define CACHE_TTL 30

const char IP_ERROR[100] = { '\0','\0','\0' ,'\0' };


int d_or_f(char* s, int len) {//判断输入的是DNSSever还是fileName，全是数字和.则为DNSSever
    int d_flag = 1;
    for (int i = 0; i < len; i++) {
        if ((s[i] > '9' || s[i] < '0') && s[i] != '.') {
            d_flag = 0;
            break;
        }
    }
    return d_flag;
}
int paramater_set(int argc, char** argv, int* outputLevel, char* DNSServer, char* fileName) {//根据命令行参数进行解析，根据不同的参数设置日志级别outputLevel、DNS服务器地址DNSServer以及文件名fileName
    int noneflag = 0;

    switch (argc) {
    case 1://对应无参数
        *outputLevel = noneDebug;
        strcpy(DNSServer, defaultDNSServer);
        strcpy(fileName, defaultFileName);
        break;
    case 2:
        if (argv[1][0] == '-') {// -d或者 - dd
            if (strcmp(argv[1], "-d") == 0) {
                *outputLevel = oneDebug;
            }
            else if (strcmp(argv[1], "-dd") == 0) {
                *outputLevel = twoDebug;
            }
            strcpy(DNSServer, defaultDNSServer);
            strcpy(fileName, defaultFileName);
            break;
        }
        if (d_or_f(argv[1], strlen(argv[1])) == 1) {//DNSSever
            *outputLevel = noneDebug;
            strcpy(DNSServer, argv[1]);
            strcpy(fileName, defaultFileName);
            break;
        }
        else {//fileName
            *outputLevel = noneDebug;
            strcpy(DNSServer, defaultDNSServer);
            strcpy(fileName, argv[1]);
            break;
        }
    case 3:
        if (argv[1][0] == '-') {//-d or -dd
            if (d_or_f(argv[2], strlen(argv[2])) == 1) {//+ DNSSever
                if (strcmp(argv[1], "-d") == 0) {
                    *outputLevel = oneDebug;
                }
                else if (strcmp(argv[1], "-dd") == 0) {
                    *outputLevel = twoDebug;
                }
                strcpy(DNSServer, argv[2]);
                strcpy(fileName, defaultFileName);
            }
            else {//+ fileName
                if (strcmp(argv[1], "-d") == 0) {
                    *outputLevel = oneDebug;
                }
                else if (strcmp(argv[1], "-dd") == 0) {
                    *outputLevel = twoDebug;
                }
                strcpy(DNSServer, defaultDNSServer);
                strcpy(fileName, argv[2]);
            }
        }
        else {//DNSSever fileName
            *outputLevel = noneDebug;
            strcpy(DNSServer, argv[1]);
            strcpy(fileName, argv[2]);
        }
        break;
    case 4:// -d or -dd DNSSever fileName
        if (strcmp(argv[1], "-d") == 0) {
            *outputLevel = oneDebug;
        }
        else if (strcmp(argv[1], "-dd") == 0) {
            *outputLevel = twoDebug;
        }
        strcpy(DNSServer, argv[2]);
        strcpy(fileName, argv[3]);
        break;
    default:
        noneflag = 1;
        break;
    }
    return noneflag;
}


struct header {//DNS报文头结构12个字节
    unsigned short ID;//2B = 16 bits，id
    int QR;//1bit，Query or Response，查询/响应的标志位，0为查询，1为响应
    unsigned short Opcode;//4bits,operationCode,通常值为 0 表示标准查询，其他值为 1 表示反向查询， 2 表示服务器状态请求等
    int AA;//1bit,权威回答 (Authoritative answer),1表示该服务器为权威服务器
    int TC;//1bit,截断标志 (Truncated ),1表示响应长度超过 512 字节时，只返回前 512 个字节
    int RD;//1bit，1表示用户希望使用递归查询 (Recursion desired)
    int RA;//1bit，递归可用 (Recursion Available)，如果服务器支持递归查询，则响应中该位为 1
    int Z;//3bits,保留位为 0，该字段
    unsigned int RCODE;//4bits,响应码 (Response coded) 表示响应状态,0表示无错误，3表示域名不存在

    //RR,resource record
    unsigned short QDCOUNT;//2B，question section 问题数量
    unsigned short ANCOUNT;//2B，answer section 中 RR 数量
    unsigned short NSCOUNT;//2B，authority records section 中 RR 数量
    unsigned short ARCOUNT;//2B，additional records section 中 RR 数量
}myHeader;

void setHeader(struct header* myheader, char* buf) {//从一个DNS报文的头部读取信息，并将这些信息存储到struct header中
    //前2个字节读取id
    unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
    memcpy(t, buf, sizeof(unsigned short));
    myheader->ID = ntohs(*t);//ntohs 将网络字节顺序的 16 位无符号整数转换为主机字节顺序，得到 DNS 报文的事务 ID
    memset(t, 0, sizeof(t));

    int bits[8];
    //从buf[2]字节中解析DNS报文的标志位
    bits[0] = ((buf[2] & 0x01) == 0x01) ? 1 : 0;
    bits[1] = ((buf[2] & 0x02) == 0x02) ? 1 : 0;
    bits[2] = ((buf[2] & 0x04) == 0x04) ? 1 : 0;
    bits[3] = ((buf[2] & 0x08) == 0x08) ? 1 : 0;
    bits[4] = ((buf[2] & 0x10) == 0x10) ? 1 : 0;
    bits[5] = ((buf[2] & 0x20) == 0x20) ? 1 : 0;
    bits[6] = ((buf[2] & 0x40) == 0x40) ? 1 : 0;
    bits[7] = ((buf[2] & 0x80) == 0x80) ? 1 : 0;
    myheader->QR = bits[7];
    myheader->Opcode = bits[3] + bits[4] * 2 + bits[5] * 4 + bits[6] * 8;
    myheader->AA = bits[2];
    myheader->TC = bits[1];
    myheader->RD = bits[0];
    //从buf[3]字节中解析DNS报文的标志位
    bits[0] = ((buf[3] & 0x01) == 0x01) ? 1 : 0;
    bits[1] = ((buf[3] & 0x02) == 0x02) ? 1 : 0;
    bits[2] = ((buf[3] & 0x04) == 0x04) ? 1 : 0;
    bits[3] = ((buf[3] & 0x08) == 0x08) ? 1 : 0;
    bits[4] = ((buf[3] & 0x10) == 0x10) ? 1 : 0;
    bits[5] = ((buf[3] & 0x20) == 0x20) ? 1 : 0;
    bits[6] = ((buf[3] & 0x40) == 0x40) ? 1 : 0;
    bits[7] = ((buf[3] & 0x80) == 0x80) ? 1 : 0;
    myheader->RCODE = bits[0] + bits[1] * 2 + bits[2] * 4 + bits[3] * 8;
    myheader->Z = bits[4] + bits[5] * 2 + bits[6] * 4;//保留0
    myheader->RA = bits[7];
    //从buf[4]到buf[11]的8个字节中读取各个字段
    memcpy(t, &buf[4], sizeof(unsigned short));
    myheader->QDCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[6], sizeof(unsigned short));
    myheader->ANCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[8], sizeof(unsigned short));
    myheader->NSCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

    memcpy(t, &buf[10], sizeof(unsigned short));
    myheader->ARCOUNT = ntohs(*t);
    memset(t, 0, sizeof(t));

}

void printHeader(struct header* myHeader) {
    printf("头部信息:\n");
    printf("\tID = %u   ", myHeader->ID);
    printf("QR = %u   ", myHeader->QR);
    printf("Opcode = %u   ", myHeader->Opcode);
    printf("AA = %u   ", myHeader->AA);
    printf("TC = %u   ", myHeader->TC);
    printf("RD = %u   ", myHeader->RD);
    printf("RA = %u   ", myHeader->RA);
    printf("Z = %u\n", myHeader->Z);
    printf("\tRCODE = %u   ", myHeader->RCODE);
    printf("QDCOUNT = %u   ", myHeader->QDCOUNT);
    printf("ANCOUNT = %u   ", myHeader->ANCOUNT);
    printf("NSCOUNT = %u   ", myHeader->NSCOUNT);
    printf("ARCOUNT = %u\n", myHeader->ARCOUNT);

}

void printBuf(char* buf, int buflen) {//将buf按wireshark格式输出
    for (int i = 0; i < buflen; i++) {
        if ((buf[i] & 0xf0) == 0x00) printf("0");
        //输出十六进制数
        printf("%x ", (unsigned char)buf[i]);
    }
    puts("");
}



struct id_transfer {
    unsigned short oldID;//旧ID
    int done;//是否已经完成
    SOCKADDR_IN clientAddr;//客户端套接字地址
    time_t ttl_end;//缓存记录的过期时间，即DNS记录的资源记录的生存时间（Time To Live, TTL）的结束时间
    char url[100];// 存储客户端请求的URL相关信息
    int timeout;
};


#define Mem(arr, val) memset(arr, val, sizeof(arr))

struct ip {
    char ip[100];
    //time_t ttl_rend;//该IP地址记录的剩余生存时间（TTL Remaining End Time）的结束时间
};

struct cache {
    char url[100];//domainname
    int ip_num;//ip地址数量
    struct ip Ip[100];
    time_t ttl_end;//过期时间
};

struct cache Cache[10000];
int cache_num = 0;

int if_in_cache(char* url) {//判断请求的URL是否存在于缓存中，如果存在则返回相应的缓存位置，如果不存在于缓存中，则返回0
    for (int i = 1; i <= cache_num; i++) {
        if (Cache[i].ttl_end <= time(NULL)) {
            Cache[i] = Cache[cache_num];
            Cache[cache_num].ip_num = 0;
            cache_num--;
            //printf("缓存已过期\n");
        }
        else {
            if (strcmp(Cache[i].url, url) == 0) {  //当前请求的 URL 与缓存中的 URL相同，找到匹配的缓存项
                return i;
            }
        }
    }
    return 0;
}



typedef struct ipUrlNode {
    char ip[100];
    char url[100];
}IpUrlNode;
IpUrlNode ipUrlNodeSeq[IP_URL_MAX];
int ipUrlNodeNum = 0;  //记录数量

void init_ip_url_table(char* fileName, int outputLevel) {//将dnsrelay.txt存储到ipUrlNodeseq中
    FILE* fp = NULL;
    fp = fopen(fileName, "r");

    if (fp == NULL) {
        printf("dnsrelay.txt打开失败,程序退出!\n");
        exit(0);
    }

    char _ip[100]; memset(_ip, 0, sizeof(_ip));
    char _url[100];
    int findFlag = 0;
    if (outputLevel == twoDebug)
        printf("\n内部资源列表:\n");
    while (!feof(fp)) {
        int x1, x2, x3, x4;
        fscanf(fp, "%d%*c%d%*c%d%*c%d %s", &x1, &x2, &x3, &x4, _url);
        _ip[0] = x1;
        _ip[1] = x2;
        _ip[2] = x3;
        _ip[3] = x4;

        ipUrlNodeNum++;
        strcpy(ipUrlNodeSeq[ipUrlNodeNum].ip, _ip);
        strcpy(ipUrlNodeSeq[ipUrlNodeNum].url, _url);

        if (outputLevel == twoDebug) {
            printf("\t%d: ", ipUrlNodeNum);
            for (int i = 0; i < 4; i++) {
                printf("%u", (unsigned char)_ip[i]);
                if (i != 3) {
                    printf(".");
                }
                else {
                    printf("      ");
                }
            }
            printf("%s\n", _url);
        }
    }

}
int num;//查询过程中找到的 IP 地址数量
char ip[20][100];//存储从内部资源或缓存中找到的 IP 地址列表

void cache_to_ip(int which_url) {//从缓存中获取对应URL的IP地址列表，并将其复制到全局数组 ip[] 中
    num = Cache[which_url].ip_num;
    for (int i = 1; i <= num; i++) {
        strcpy(ip[i], Cache[which_url].Ip[i].ip);
    }
}
void makeUdpMessage(char* recvBuf, char* sendBuf, int num, int recvLen, int* len, int outputLevel) {//recvBuf只包含头部和问题部分，recvBuf不变，将响应信息存储到sendBuf中

    //将sendBuf复制请求报文
    for (int i = 0; i < 512; i++) {
        sendBuf[i] = recvBuf[i];
    }

    //================头部===============
    //ID一致，sendBuf[0~1]
    unsigned short us;
    //QR=1，OPCODE=0，AA=0,TC=0,RD=1,RA=1,Z=0,RCOED=0/3，sendBuf[2~3]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        us = htons(0x8183);//RCODE=3，表示域名不存在
        if (outputLevel == twoDebug) printf("\n返回0.0.0.0，查询失败，域名不存在，将向客户端发送错误响应报文!\n\n");
    }
    else {
        us = htons(0x8180);//RCODE=0，表示成功
        if (outputLevel == twoDebug) {
            for (int i = 1; i <= num; i++) {
                printf("\t");
                for (int j = 0; j < 4; j++) {
                    printf("%u", (unsigned char)ip[i][j]);
                    if (j != 3) {
                        printf(".");
                    }
                    else {
                        printf("\n");
                    }
                }
            }puts("");
        }
    }
    memcpy(&sendBuf[2], &us, 2);

    //QDCOUNT，sendBuf[4~5]

    //ANCOUNT，sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //查询失败，将字节序转换为网络字节序
        us = htons(0x0000);
    }
    else {
        //查询成功，将字节序转换为网络字节序
        us = htons(0x0000 | num);
    }
    memcpy(&sendBuf[6], &us, 2);

    //NSCOUNT，sendBuf[8~9]

    //ARCOUNT，sendBuf[10~11]


    //================问题部分=============
    //已经复制完成，不需要再处理
    /*
    puts("===============");
    for (int i = 0; i < 512; i++) {

        //if ((sendBuf[i] & 0xf0) == 0x00) printf("0");
        //输出十六进制数
        printf("%x ", (unsigned char)sendBuf[i]);
    }
    puts("==================");
    */

    //================资源记录=================
    //循环处理，中间部分
    *len = recvLen;//响应报文的长度，直接在请求报文基础上修改


    //ANCOUNT，sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //查询失败，将字节序转换为网络字节序
        return;
    }

    for (int now = 1; now <= num; now++) {
        //0xc00c，NAME
        us = htons(0xc00c);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TYPE，IPV4为1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //CLASS为1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TTL=176
        unsigned long ul;
        ul = htonl(0x000000B0);
        memcpy(&sendBuf[*len], &ul, 4);
        *len += 4;

        //DATA LENGTH=4
        us = htons(0x0004);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;
        //ADDRESS
        for (int i = 0; i < 4; i++) {
            sendBuf[*len] = ip[now][i];
            *len += 1;
        }
        /*
        ul = (unsigned long)inet_addr(ip[now]);
        memcpy(&sendBuf[*len], &ul, 4);
        *len += 4;
        */
    }
}

int main(int argc, char** argv) {
    puts("Designer: 李可欣");
    int outputLevel = -1;//输出级别，0、1、2对应无、-d、-dd
    char DNSServer[100]; //Mem(DNSServer, 0);//外部DNS地址
    char fileName[100]; //Mem(fileName, 0);//内部dnsrelay文件地址

    int base = 0;

    if (paramater_set(argc, argv, &outputLevel, DNSServer, fileName) == 1) {
        printf("参数格式错误，程序退出!\n");
        return 0;
    }
    //输出outputLevel信息
    if (outputLevel == noneDebug) {
        printf("OutputLevel:noneDebug\n");
    }
    if (outputLevel == oneDebug) {
        printf("OutputLevel:oneDebug\n");
    }
    if (outputLevel == twoDebug) {
        printf("OutputLevel:twoDebug\n");
    }

    init_ip_url_table(fileName, outputLevel);//读取文件数据存入ipUrlNodeSeq

    //初始化Windows Socket API
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //创建本地DNS套接字
    SOCKET mySocket;
    mySocket = socket(AF_INET, SOCK_DGRAM, 0);//AF_INET 表示使用 IPv4 协议，SOCK_DGRAM 表示创建一个数据报套接字，UDP
    if (mySocket == SOCKET_ERROR) {
        printf("套接字创建失败\n");
        exit(1);
    }

    //绑定套接字地址
    SOCKADDR_IN myAddr;
    myAddr.sin_family = AF_INET;  //地址族
    myAddr.sin_port = htons(53);  //端口号
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY);  //sin_addr:IP 地址，套接字将绑定到所有可用接口上的 DNS 服务

    //将套接字绑定到本地DNS服务地址
    int bRes = bind(mySocket, (SOCKADDR*)&myAddr, sizeof(myAddr));
    if (bRes == SOCKET_ERROR) {
        printf("绑定失败\n");
        exit(2);
    }
    printf("绑定成功\n");

    //外部DNS套接字地址
    SOCKADDR_IN DNSAddr;
    DNSAddr.sin_family = AF_INET;
    DNSAddr.sin_port = htons(53);
    DNSAddr.sin_addr.s_addr = inet_addr(DNSServer);

    //客户端套接字地址
    SOCKADDR_IN clientAddr;
    int clientLen = sizeof(clientAddr);

    char sendBuf[512], recvBuf[512];
    Mem(recvBuf, 0);

    struct id_transfer id_trans[ID_TRANS_MAX]; //定义一个结构体数组，用于存储中间DNS原Id和套接字信息
    int id_trans_size = 0; //信息数量

    int mesNum = 0;//DNS 查询消息数量

    while (1) {
        //循环方式等待客户端请求
        Mem(recvBuf, 0);
        int recvLen = recvfrom(mySocket, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&clientAddr, &clientLen);//接收客户端发送的 DNS 查询数据，并获取客户端的地址信息
        if (outputLevel == twoDebug) {
            if (recvLen == SOCKET_ERROR) {
                printf("接收失败\n\n");
                continue;
            }
            else if (recvLen == 0) {
                printf("连接中断!\n\n");
                break;
            }
        }


        //检查是否有未收到DNS外部服务器响应且超时的请求，超时则标记为已完成并设置超时标志
        //例如143.254.64.546为外部服务器超时未响应
        for (int i = 0; i < id_trans_size; i++) {
            if (id_trans[i].done == 0 && time(NULL) >= id_trans[i].ttl_end && id_trans[i].timeout == 0) {
                id_trans[i].done = 1;
                id_trans[i].timeout = 1;
                if (outputLevel == twoDebug) printf("url of %s 超时!\n", id_trans[i].url);
            }
        }

        char url[100];
        Mem(url, 0);
        int partlen = 0;//当前url数组下标
        char* msgBuf = recvBuf + 12;//前12字节是头部信息

        //解析QNAME得到url，将url存储到url字符数组中
        char len = msgBuf[0];//该段字符长度
        int flag = 1;//当前msgBuf数组下标
        while (len != 0) {
            for (char i = 0; i < len; i++) {
                url[partlen++] = msgBuf[flag++];
            }
            len = msgBuf[flag++];
            if (len != 0) {
                url[partlen++] = '.';
            }
        }

        //QTYPE: 查询类型(A(1)、MX(15)、CNAME(5)、AAAA(28))
        //QCLASS: 查询类固定为1，表示IN
        unsigned short QTYPE, QCLASS;
        unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
        //读取QTYPE
        memcpy(t, &msgBuf[flag], sizeof(unsigned short));
        QTYPE = ntohs(*t);
        flag += 2;

        //读取QCLASS
        memcpy(t, &msgBuf[flag], sizeof(unsigned short));
        QCLASS = ntohs(*t);
        flag += 2;

        if (QTYPE != 1) {
            if (outputLevel == twoDebug)
                printf("收到非IPV4的请求!\n\n");
            continue;
        }

        /*if (QTYPE != 28 && QTYPE != 1 && QTYPE != 5 && QTYPE != 15) {
            if (outputLevel == twoDebug) printf("收到非法数据包!\n\n");
            continue;
        }*/

        mesNum++;//收到一个DNS查询消息数量加一
        if (outputLevel >= oneDebug) {
            printf("%d:    ", mesNum);
            char szIP[16];//客户端IP地址
            Mem(szIP, 0);
            strcpy(szIP, inet_ntoa(clientAddr.sin_addr));
            printf(__DATE__); printf("  ");  printf(__TIME__);
            printf("  client %s   ", szIP);
        }
        struct header myHeader;
        setHeader(&myHeader, recvBuf);//解析头部
        if (outputLevel >= oneDebug) {
            printf("%s", url);
            if (myHeader.QR == 1) {
                printf(", TYPE %d, CLASS %d\n", QTYPE, QCLASS);
            }
            else puts("");
        }
        if (outputLevel == twoDebug) {
            if (QTYPE == 28) printf("\n================收到IPV6数据包===============\n");
            else if (QTYPE == 1)printf("\n================收到IPV4数据包===============\n");
            else if (QTYPE == 5)printf("\n================收到CNAME数据包===============\n");
            else if (QTYPE == 15) printf("\n================收到MX数据包===============\n");
        }
        /*if (outputLevel == twoDebug)
            printf("\n================收到IPV4数据包===============\n");*/

        if (outputLevel == twoDebug) {
            printHeader(&myHeader);//打印头部
            printf("查询信息:\n");
            printf("\turl = %s   QTYPE = %u   QCLASS = %u\n\n\n", url, QTYPE, QCLASS);//打印查询域名、类型、类

        }

        if (myHeader.QR == 0) {//收到查询包
            num = 0;
            memset(ip, 0, sizeof(ip));
            int findFlag = 0;//0表示未找到，1表示找到
            int which_url = if_in_cache(url);//在缓存中的第一位

            if (QTYPE != 1) which_url = 0;//只判断ipv4是否在缓存中

            if (which_url != 0) {
                if (outputLevel == twoDebug) printf("在cache中找到对应ip，将向客户端发送响应报文!\n");
                cache_to_ip(which_url);
                //将从缓存中获取的IP地址信息进行处理

                //构造要发送给客户端的响应报文
                int len;
                makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);

                struct header sendHeader;
                setHeader(&sendHeader, sendBuf);
                //当输出级别为2时，打印响应报文信息
                if (outputLevel == twoDebug) {
                    printf("要发送给客户端的响应报文:\n");
                    printHeader(&sendHeader);

                    printf("响应原始信息:\n");
                    printBuf(sendBuf, len);
                }

                int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);//发送响应报文
                if (outputLevel == twoDebug) {
                    if (sendFlag == SOCKET_ERROR) {
                        printf("\n(缓存)向客户端发送响应报文失败!\n\n");
                    }
                    else {
                        printf("\n(缓存)向客户端发送响应报文成功!\n\n");
                    }
                    puts("===============================================\n\n\n");
                }
            }
            else {
                if (outputLevel == twoDebug)
                    printf("在cache中未找到对应ip\n");
                for (int i = 1; i <= ipUrlNodeNum; i++) {
                    if (strcmp(ipUrlNodeSeq[i].url, url) == 0) {
                        findFlag = 1;
                        num++;
                        memcpy(ip[num], ipUrlNodeSeq[i].ip, sizeof(ip[num]));
                    }
                }
                if (QTYPE != 1) findFlag = 0;
                if (findFlag == 1) {
                    /*// 在内部查询数据库中找到
                    if (findFlag == 1) {
                      // 如果已经存在于缓存中，更新缓存有效期
                        int which_url = if_in_cache(url);
                        if (which_url != 0) {
                            Cache[which_url].ttl_end = time(NULL) + CACHE_TTL; // 更新缓存有效期
                        } else {
                            // 如果不存在于缓存中，添加到缓存
                            cache_num++;
                            strcpy(Cache[cache_num].url, url);
                            Cache[cache_num].ip_num = num;
                            for (int i = 1; i <= num; i++) {
                                strcpy(Cache[cache_num].Ip[i].ip, ip[i]);
                            }
                            Cache[cache_num].ttl_end = time(NULL) + CACHE_TTL;
                        }
                    }
                    */
                    if (outputLevel == twoDebug)
                        printf("在内部资源中找到对应ip，将向客户端发送响应报文!\n");

                    //构造响应报文并返回给client
                    int len;
                    makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);//原样复制，根据ip数组修改，recvBuf不变

                    struct header sendHeader;
                    setHeader(&sendHeader, sendBuf);
                    if (outputLevel == twoDebug) {
                        printf("要发送给客户端的响应报文:\n");
                        printHeader(&sendHeader);

                        printf("响应原始信息:\n");
                        printBuf(sendBuf, len);
                    }

                    //发送响应报文
                    int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
                    if (outputLevel == twoDebug) {
                        if (sendFlag == SOCKET_ERROR) {
                            printf("\n(内部资源)向客户端发送响应报文失败!\n\n");
                        }
                        else {
                            printf("\n(内部资源)向客户端发送响应报文成功!\n\n");
                        }
                        puts("===============================================\n\n\n");
                    }
                }

                //文件中无记录
                else {
                    if (outputLevel == twoDebug) printf("在内部资源中未找到对应ip，将向外部DNS服务器发送查询报文!\n");
                    unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
                    memcpy(t, recvBuf, sizeof(unsigned short));
                    unsigned short oldID = ntohs(*t);
                    struct id_transfer myTransfer;
                    myTransfer.oldID = oldID;
                    myTransfer.clientAddr = clientAddr;
                    myTransfer.done = 0;
                    myTransfer.ttl_end = time(NULL) + DNSSERVER_NO_REPLY;
                    strcpy(myTransfer.url, url);
                    myTransfer.timeout = 0;

                    //id_trans数组用于记录id转换关系，每个元素包含原始id、客户端收到的id、是否已经完成、是否收到dns服务器响应、客户端的clientAddr、收到dns服务器响应后转发给该clientAddr

                    //如果id_trans数组满了则pop前一半，base作为循环队列的偏移量，size-base为有效元素个数
                    //自定义数组size为1000为例，base可以调整为队列循环的原因，pop前500个元素，新增的id应从501开始，base应设置为500
                    //再新增500个id应从1开始，base应重新设置为0，因此每次满了base在0和500之间切换一次

                    if (id_trans_size == ID_TRANS_MAX) {
                        for (int i = 0; i < ID_TRANS_MAX / 2; i++) {
                            id_trans[i] = id_trans[i + ID_TRANS_MAX / 2];
                        }
                        base = ID_TRANS_MAX / 2 - base;
                        id_trans_size = ID_TRANS_MAX / 2;
                    }

                    //生成新的id
                    unsigned short newID = (unsigned short)((base + id_trans_size) % ID_TRANS_MAX);
                    newID = htons(newID);
                    memcpy(recvBuf, &newID, sizeof(unsigned short));//将生成的新 ID 复制到查询信息的头部，替换原始的 ID
                    //打印ID
                    if (outputLevel == twoDebug) {
                        printf("ID转换：旧ID为%u，新ID为%u\n", oldID, newID);
                    }

                    id_trans[id_trans_size] = myTransfer;
                    id_trans_size++;

                    int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&DNSAddr, sizeof(DNSAddr));
                    if (outputLevel == twoDebug) {
                        if (sendLen == SOCKET_ERROR) {
                            printf("\n向外部DNS服务器发送查询报文失败!\n\n");
                        }
                        else {
                            printf("\n向外部DNS服务器发送查询报文成功!\n\n");
                        }
                        puts("===============================================\n\n\n");
                    }


                }
            }
        }
        else if (myHeader.QR == 1) {//收到响应包
            if (QTYPE == 1) {
                msgBuf = recvBuf + 12;
                char len1 = msgBuf[0];
                flag = 1;
                char url0[100] = "";
                while (len1 != 0) {
                    for (char i = 0; i < len1; i++) {
                        url0[strlen(url0)] = msgBuf[flag++];
                    }
                    len1 = msgBuf[flag++];
                    if (len1 != 0) {
                        url0[strlen(url0)] = '.';
                    }
                }
                cache_num++;
                strcpy(Cache[cache_num].url, url0);

                flag = flag + 4;
                char qtype = 0;
                for (short j = 0; j < myHeader.ANCOUNT; j++) {
                    Cache[cache_num].ip_num++;
                    flag = flag + 3;
                    qtype = msgBuf[flag];
                    flag = flag + 3;
                    for (int i = 1; i <= 4; i++) {
                        flag++;
                    }
                    if (qtype == 1) {
                        Cache[cache_num].ttl_end = CACHE_TTL + time(NULL);
                        flag = flag + 2;
                        for (int i = 0; i < 4; i++) {
                            Cache[cache_num].Ip[Cache[cache_num].ip_num].ip[i] = (unsigned char)msgBuf[flag++];
                            //将收到的IP地址信息提取出来并存储到缓存中
                        }
                        // 将域名和对应的 IP 地址添加到 ipUrlNodeSeq 中
                        if (ipUrlNodeNum < IP_URL_MAX) {
                            ipUrlNodeNum++;
                            strcpy(ipUrlNodeSeq[ipUrlNodeNum].url, url0);
                            memcpy(ipUrlNodeSeq[ipUrlNodeNum].ip, Cache[cache_num].Ip[Cache[cache_num].ip_num].ip, 4);
                            if (outputLevel == twoDebug) {
                                printf("将域名 %s 及其 IP 地址 %u.%u.%u.%u 添加到内部资源列表中\n", url0,
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[0],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[1],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[2],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[3]);
                            }
                        }
                    }
                    //如果不是IPv4信息，忽略该记录，同时将缓存记录清空
                    else {
                        Cache[cache_num].ip_num = 0;
                        Mem(Cache[cache_num].url, 0);
                        cache_num--;
                        break;
                    }
                }
            }

            unsigned short* newID = (unsigned short*)malloc(sizeof(unsigned short));
            memcpy(newID, &recvBuf, sizeof(unsigned int));
            /*if (outputLevel == twoDebug) {
                printf("ID转换：新ID为%u，", newID);
            }*/
            //通过响应信息ID找到旧ID
            *newID = ntohs(*newID);
            int find = (base + (int)*newID) % ID_TRANS_MAX;
            if (id_trans[find].done == 1) {
                continue;
            }//客户端的请求已经处理，不需要再响应

            unsigned short oldID = id_trans[find].oldID;
            /*if (outputLevel == twoDebug) {
                printf("旧ID为%u\n", oldID);
            }*/
            oldID = htons(oldID);
            memcpy(recvBuf, &oldID, sizeof(unsigned short));  //将响应信息ID替换回客户端请求中的oldID
            id_trans[find].done = 1;  //标记为已处理

            //打印
            struct header sendHeader;
            setHeader(&sendHeader, recvBuf);
            if (outputLevel == twoDebug) {
                printf("要发送给客户端的响应报文:\n");
                printHeader(&sendHeader);

                printf("响应原始信息:\n");
                printBuf(recvBuf, recvLen);
            }
            //发送响应
            int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
            if (outputLevel == twoDebug) {
                if (sendLen == SOCKET_ERROR) {
                    printf("\n向客户端发送响应报文失败!\n\n");
                }
                else {
                    printf("\n向客户端发送响应报文成功!\n\n");
                }
                puts("===============================================\n\n\n");
            }
        }
    }
    //关闭套接字
    closesocket(mySocket);
    WSACleanup();
}