#include <winsock2.h>
#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib, "ws2_32.lib")  //���� ws2_32.dll
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


int d_or_f(char* s, int len) {//�ж��������DNSSever����fileName��ȫ�����ֺ�.��ΪDNSSever
    int d_flag = 1;
    for (int i = 0; i < len; i++) {
        if ((s[i] > '9' || s[i] < '0') && s[i] != '.') {
            d_flag = 0;
            break;
        }
    }
    return d_flag;
}
int paramater_set(int argc, char** argv, int* outputLevel, char* DNSServer, char* fileName) {//���������в������н��������ݲ�ͬ�Ĳ���������־����outputLevel��DNS��������ַDNSServer�Լ��ļ���fileName
    int noneflag = 0;

    switch (argc) {
    case 1://��Ӧ�޲���
        *outputLevel = noneDebug;
        strcpy(DNSServer, defaultDNSServer);
        strcpy(fileName, defaultFileName);
        break;
    case 2:
        if (argv[1][0] == '-') {// -d���� - dd
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


struct header {//DNS����ͷ�ṹ12���ֽ�
    unsigned short ID;//2B = 16 bits��id
    int QR;//1bit��Query or Response����ѯ/��Ӧ�ı�־λ��0Ϊ��ѯ��1Ϊ��Ӧ
    unsigned short Opcode;//4bits,operationCode,ͨ��ֵΪ 0 ��ʾ��׼��ѯ������ֵΪ 1 ��ʾ�����ѯ�� 2 ��ʾ������״̬�����
    int AA;//1bit,Ȩ���ش� (Authoritative answer),1��ʾ�÷�����ΪȨ��������
    int TC;//1bit,�ضϱ�־ (Truncated ),1��ʾ��Ӧ���ȳ��� 512 �ֽ�ʱ��ֻ����ǰ 512 ���ֽ�
    int RD;//1bit��1��ʾ�û�ϣ��ʹ�õݹ��ѯ (Recursion desired)
    int RA;//1bit���ݹ���� (Recursion Available)�����������֧�ֵݹ��ѯ������Ӧ�и�λΪ 1
    int Z;//3bits,����λΪ 0�����ֶ�
    unsigned int RCODE;//4bits,��Ӧ�� (Response coded) ��ʾ��Ӧ״̬,0��ʾ�޴���3��ʾ����������

    //RR,resource record
    unsigned short QDCOUNT;//2B��question section ��������
    unsigned short ANCOUNT;//2B��answer section �� RR ����
    unsigned short NSCOUNT;//2B��authority records section �� RR ����
    unsigned short ARCOUNT;//2B��additional records section �� RR ����
}myHeader;

void setHeader(struct header* myheader, char* buf) {//��һ��DNS���ĵ�ͷ����ȡ��Ϣ��������Щ��Ϣ�洢��struct header��
    //ǰ2���ֽڶ�ȡid
    unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
    memcpy(t, buf, sizeof(unsigned short));
    myheader->ID = ntohs(*t);//ntohs �������ֽ�˳��� 16 λ�޷�������ת��Ϊ�����ֽ�˳�򣬵õ� DNS ���ĵ����� ID
    memset(t, 0, sizeof(t));

    int bits[8];
    //��buf[2]�ֽ��н���DNS���ĵı�־λ
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
    //��buf[3]�ֽ��н���DNS���ĵı�־λ
    bits[0] = ((buf[3] & 0x01) == 0x01) ? 1 : 0;
    bits[1] = ((buf[3] & 0x02) == 0x02) ? 1 : 0;
    bits[2] = ((buf[3] & 0x04) == 0x04) ? 1 : 0;
    bits[3] = ((buf[3] & 0x08) == 0x08) ? 1 : 0;
    bits[4] = ((buf[3] & 0x10) == 0x10) ? 1 : 0;
    bits[5] = ((buf[3] & 0x20) == 0x20) ? 1 : 0;
    bits[6] = ((buf[3] & 0x40) == 0x40) ? 1 : 0;
    bits[7] = ((buf[3] & 0x80) == 0x80) ? 1 : 0;
    myheader->RCODE = bits[0] + bits[1] * 2 + bits[2] * 4 + bits[3] * 8;
    myheader->Z = bits[4] + bits[5] * 2 + bits[6] * 4;//����0
    myheader->RA = bits[7];
    //��buf[4]��buf[11]��8���ֽ��ж�ȡ�����ֶ�
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
    printf("ͷ����Ϣ:\n");
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

void printBuf(char* buf, int buflen) {//��buf��wireshark��ʽ���
    for (int i = 0; i < buflen; i++) {
        if ((buf[i] & 0xf0) == 0x00) printf("0");
        //���ʮ��������
        printf("%x ", (unsigned char)buf[i]);
    }
    puts("");
}



struct id_transfer {
    unsigned short oldID;//��ID
    int done;//�Ƿ��Ѿ����
    SOCKADDR_IN clientAddr;//�ͻ����׽��ֵ�ַ
    time_t ttl_end;//�����¼�Ĺ���ʱ�䣬��DNS��¼����Դ��¼������ʱ�䣨Time To Live, TTL���Ľ���ʱ��
    char url[100];// �洢�ͻ��������URL�����Ϣ
    int timeout;
};


#define Mem(arr, val) memset(arr, val, sizeof(arr))

struct ip {
    char ip[100];
    //time_t ttl_rend;//��IP��ַ��¼��ʣ������ʱ�䣨TTL Remaining End Time���Ľ���ʱ��
};

struct cache {
    char url[100];//domainname
    int ip_num;//ip��ַ����
    struct ip Ip[100];
    time_t ttl_end;//����ʱ��
};

struct cache Cache[10000];
int cache_num = 0;

int if_in_cache(char* url) {//�ж������URL�Ƿ�����ڻ����У���������򷵻���Ӧ�Ļ���λ�ã�����������ڻ����У��򷵻�0
    for (int i = 1; i <= cache_num; i++) {
        if (Cache[i].ttl_end <= time(NULL)) {
            Cache[i] = Cache[cache_num];
            Cache[cache_num].ip_num = 0;
            cache_num--;
            //printf("�����ѹ���\n");
        }
        else {
            if (strcmp(Cache[i].url, url) == 0) {  //��ǰ����� URL �뻺���е� URL��ͬ���ҵ�ƥ��Ļ�����
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
int ipUrlNodeNum = 0;  //��¼����

void init_ip_url_table(char* fileName, int outputLevel) {//��dnsrelay.txt�洢��ipUrlNodeseq��
    FILE* fp = NULL;
    fp = fopen(fileName, "r");

    if (fp == NULL) {
        printf("dnsrelay.txt��ʧ��,�����˳�!\n");
        exit(0);
    }

    char _ip[100]; memset(_ip, 0, sizeof(_ip));
    char _url[100];
    int findFlag = 0;
    if (outputLevel == twoDebug)
        printf("\n�ڲ���Դ�б�:\n");
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
int num;//��ѯ�������ҵ��� IP ��ַ����
char ip[20][100];//�洢���ڲ���Դ�򻺴����ҵ��� IP ��ַ�б�

void cache_to_ip(int which_url) {//�ӻ����л�ȡ��ӦURL��IP��ַ�б������临�Ƶ�ȫ������ ip[] ��
    num = Cache[which_url].ip_num;
    for (int i = 1; i <= num; i++) {
        strcpy(ip[i], Cache[which_url].Ip[i].ip);
    }
}
void makeUdpMessage(char* recvBuf, char* sendBuf, int num, int recvLen, int* len, int outputLevel) {//recvBufֻ����ͷ�������ⲿ�֣�recvBuf���䣬����Ӧ��Ϣ�洢��sendBuf��

    //��sendBuf����������
    for (int i = 0; i < 512; i++) {
        sendBuf[i] = recvBuf[i];
    }

    //================ͷ��===============
    //IDһ�£�sendBuf[0~1]
    unsigned short us;
    //QR=1��OPCODE=0��AA=0,TC=0,RD=1,RA=1,Z=0,RCOED=0/3��sendBuf[2~3]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        us = htons(0x8183);//RCODE=3����ʾ����������
        if (outputLevel == twoDebug) printf("\n����0.0.0.0����ѯʧ�ܣ����������ڣ�����ͻ��˷��ʹ�����Ӧ����!\n\n");
    }
    else {
        us = htons(0x8180);//RCODE=0����ʾ�ɹ�
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

    //QDCOUNT��sendBuf[4~5]

    //ANCOUNT��sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //��ѯʧ�ܣ����ֽ���ת��Ϊ�����ֽ���
        us = htons(0x0000);
    }
    else {
        //��ѯ�ɹ������ֽ���ת��Ϊ�����ֽ���
        us = htons(0x0000 | num);
    }
    memcpy(&sendBuf[6], &us, 2);

    //NSCOUNT��sendBuf[8~9]

    //ARCOUNT��sendBuf[10~11]


    //================���ⲿ��=============
    //�Ѿ�������ɣ�����Ҫ�ٴ���
    /*
    puts("===============");
    for (int i = 0; i < 512; i++) {

        //if ((sendBuf[i] & 0xf0) == 0x00) printf("0");
        //���ʮ��������
        printf("%x ", (unsigned char)sendBuf[i]);
    }
    puts("==================");
    */

    //================��Դ��¼=================
    //ѭ�������м䲿��
    *len = recvLen;//��Ӧ���ĵĳ��ȣ�ֱ���������Ļ������޸�


    //ANCOUNT��sendBuf[6~7]
    if (strcmp(ip[1], IP_ERROR) == 0) {
        //��ѯʧ�ܣ����ֽ���ת��Ϊ�����ֽ���
        return;
    }

    for (int now = 1; now <= num; now++) {
        //0xc00c��NAME
        us = htons(0xc00c);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //TYPE��IPV4Ϊ1
        us = htons(0x0001);
        memcpy(&sendBuf[*len], &us, 2);
        *len += 2;

        //CLASSΪ1
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
    puts("Designer: �����");
    int outputLevel = -1;//�������0��1��2��Ӧ�ޡ�-d��-dd
    char DNSServer[100]; //Mem(DNSServer, 0);//�ⲿDNS��ַ
    char fileName[100]; //Mem(fileName, 0);//�ڲ�dnsrelay�ļ���ַ

    int base = 0;

    if (paramater_set(argc, argv, &outputLevel, DNSServer, fileName) == 1) {
        printf("������ʽ���󣬳����˳�!\n");
        return 0;
    }
    //���outputLevel��Ϣ
    if (outputLevel == noneDebug) {
        printf("OutputLevel:noneDebug\n");
    }
    if (outputLevel == oneDebug) {
        printf("OutputLevel:oneDebug\n");
    }
    if (outputLevel == twoDebug) {
        printf("OutputLevel:twoDebug\n");
    }

    init_ip_url_table(fileName, outputLevel);//��ȡ�ļ����ݴ���ipUrlNodeSeq

    //��ʼ��Windows Socket API
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //��������DNS�׽���
    SOCKET mySocket;
    mySocket = socket(AF_INET, SOCK_DGRAM, 0);//AF_INET ��ʾʹ�� IPv4 Э�飬SOCK_DGRAM ��ʾ����һ�����ݱ��׽��֣�UDP
    if (mySocket == SOCKET_ERROR) {
        printf("�׽��ִ���ʧ��\n");
        exit(1);
    }

    //���׽��ֵ�ַ
    SOCKADDR_IN myAddr;
    myAddr.sin_family = AF_INET;  //��ַ��
    myAddr.sin_port = htons(53);  //�˿ں�
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY);  //sin_addr:IP ��ַ���׽��ֽ��󶨵����п��ýӿ��ϵ� DNS ����

    //���׽��ְ󶨵�����DNS�����ַ
    int bRes = bind(mySocket, (SOCKADDR*)&myAddr, sizeof(myAddr));
    if (bRes == SOCKET_ERROR) {
        printf("��ʧ��\n");
        exit(2);
    }
    printf("�󶨳ɹ�\n");

    //�ⲿDNS�׽��ֵ�ַ
    SOCKADDR_IN DNSAddr;
    DNSAddr.sin_family = AF_INET;
    DNSAddr.sin_port = htons(53);
    DNSAddr.sin_addr.s_addr = inet_addr(DNSServer);

    //�ͻ����׽��ֵ�ַ
    SOCKADDR_IN clientAddr;
    int clientLen = sizeof(clientAddr);

    char sendBuf[512], recvBuf[512];
    Mem(recvBuf, 0);

    struct id_transfer id_trans[ID_TRANS_MAX]; //����һ���ṹ�����飬���ڴ洢�м�DNSԭId���׽�����Ϣ
    int id_trans_size = 0; //��Ϣ����

    int mesNum = 0;//DNS ��ѯ��Ϣ����

    while (1) {
        //ѭ����ʽ�ȴ��ͻ�������
        Mem(recvBuf, 0);
        int recvLen = recvfrom(mySocket, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&clientAddr, &clientLen);//���տͻ��˷��͵� DNS ��ѯ���ݣ�����ȡ�ͻ��˵ĵ�ַ��Ϣ
        if (outputLevel == twoDebug) {
            if (recvLen == SOCKET_ERROR) {
                printf("����ʧ��\n\n");
                continue;
            }
            else if (recvLen == 0) {
                printf("�����ж�!\n\n");
                break;
            }
        }


        //����Ƿ���δ�յ�DNS�ⲿ��������Ӧ�ҳ�ʱ�����󣬳�ʱ����Ϊ����ɲ����ó�ʱ��־
        //����143.254.64.546Ϊ�ⲿ��������ʱδ��Ӧ
        for (int i = 0; i < id_trans_size; i++) {
            if (id_trans[i].done == 0 && time(NULL) >= id_trans[i].ttl_end && id_trans[i].timeout == 0) {
                id_trans[i].done = 1;
                id_trans[i].timeout = 1;
                if (outputLevel == twoDebug) printf("url of %s ��ʱ!\n", id_trans[i].url);
            }
        }

        char url[100];
        Mem(url, 0);
        int partlen = 0;//��ǰurl�����±�
        char* msgBuf = recvBuf + 12;//ǰ12�ֽ���ͷ����Ϣ

        //����QNAME�õ�url����url�洢��url�ַ�������
        char len = msgBuf[0];//�ö��ַ�����
        int flag = 1;//��ǰmsgBuf�����±�
        while (len != 0) {
            for (char i = 0; i < len; i++) {
                url[partlen++] = msgBuf[flag++];
            }
            len = msgBuf[flag++];
            if (len != 0) {
                url[partlen++] = '.';
            }
        }

        //QTYPE: ��ѯ����(A(1)��MX(15)��CNAME(5)��AAAA(28))
        //QCLASS: ��ѯ��̶�Ϊ1����ʾIN
        unsigned short QTYPE, QCLASS;
        unsigned short* t = (unsigned short*)malloc(sizeof(unsigned short));
        //��ȡQTYPE
        memcpy(t, &msgBuf[flag], sizeof(unsigned short));
        QTYPE = ntohs(*t);
        flag += 2;

        //��ȡQCLASS
        memcpy(t, &msgBuf[flag], sizeof(unsigned short));
        QCLASS = ntohs(*t);
        flag += 2;

        if (QTYPE != 1) {
            if (outputLevel == twoDebug)
                printf("�յ���IPV4������!\n\n");
            continue;
        }

        /*if (QTYPE != 28 && QTYPE != 1 && QTYPE != 5 && QTYPE != 15) {
            if (outputLevel == twoDebug) printf("�յ��Ƿ����ݰ�!\n\n");
            continue;
        }*/

        mesNum++;//�յ�һ��DNS��ѯ��Ϣ������һ
        if (outputLevel >= oneDebug) {
            printf("%d:    ", mesNum);
            char szIP[16];//�ͻ���IP��ַ
            Mem(szIP, 0);
            strcpy(szIP, inet_ntoa(clientAddr.sin_addr));
            printf(__DATE__); printf("  ");  printf(__TIME__);
            printf("  client %s   ", szIP);
        }
        struct header myHeader;
        setHeader(&myHeader, recvBuf);//����ͷ��
        if (outputLevel >= oneDebug) {
            printf("%s", url);
            if (myHeader.QR == 1) {
                printf(", TYPE %d, CLASS %d\n", QTYPE, QCLASS);
            }
            else puts("");
        }
        if (outputLevel == twoDebug) {
            if (QTYPE == 28) printf("\n================�յ�IPV6���ݰ�===============\n");
            else if (QTYPE == 1)printf("\n================�յ�IPV4���ݰ�===============\n");
            else if (QTYPE == 5)printf("\n================�յ�CNAME���ݰ�===============\n");
            else if (QTYPE == 15) printf("\n================�յ�MX���ݰ�===============\n");
        }
        /*if (outputLevel == twoDebug)
            printf("\n================�յ�IPV4���ݰ�===============\n");*/

        if (outputLevel == twoDebug) {
            printHeader(&myHeader);//��ӡͷ��
            printf("��ѯ��Ϣ:\n");
            printf("\turl = %s   QTYPE = %u   QCLASS = %u\n\n\n", url, QTYPE, QCLASS);//��ӡ��ѯ���������͡���

        }

        if (myHeader.QR == 0) {//�յ���ѯ��
            num = 0;
            memset(ip, 0, sizeof(ip));
            int findFlag = 0;//0��ʾδ�ҵ���1��ʾ�ҵ�
            int which_url = if_in_cache(url);//�ڻ����еĵ�һλ

            if (QTYPE != 1) which_url = 0;//ֻ�ж�ipv4�Ƿ��ڻ�����

            if (which_url != 0) {
                if (outputLevel == twoDebug) printf("��cache���ҵ���Ӧip������ͻ��˷�����Ӧ����!\n");
                cache_to_ip(which_url);
                //���ӻ����л�ȡ��IP��ַ��Ϣ���д���

                //����Ҫ���͸��ͻ��˵���Ӧ����
                int len;
                makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);

                struct header sendHeader;
                setHeader(&sendHeader, sendBuf);
                //���������Ϊ2ʱ����ӡ��Ӧ������Ϣ
                if (outputLevel == twoDebug) {
                    printf("Ҫ���͸��ͻ��˵���Ӧ����:\n");
                    printHeader(&sendHeader);

                    printf("��Ӧԭʼ��Ϣ:\n");
                    printBuf(sendBuf, len);
                }

                int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);//������Ӧ����
                if (outputLevel == twoDebug) {
                    if (sendFlag == SOCKET_ERROR) {
                        printf("\n(����)��ͻ��˷�����Ӧ����ʧ��!\n\n");
                    }
                    else {
                        printf("\n(����)��ͻ��˷�����Ӧ���ĳɹ�!\n\n");
                    }
                    puts("===============================================\n\n\n");
                }
            }
            else {
                if (outputLevel == twoDebug)
                    printf("��cache��δ�ҵ���Ӧip\n");
                for (int i = 1; i <= ipUrlNodeNum; i++) {
                    if (strcmp(ipUrlNodeSeq[i].url, url) == 0) {
                        findFlag = 1;
                        num++;
                        memcpy(ip[num], ipUrlNodeSeq[i].ip, sizeof(ip[num]));
                    }
                }
                if (QTYPE != 1) findFlag = 0;
                if (findFlag == 1) {
                    /*// ���ڲ���ѯ���ݿ����ҵ�
                    if (findFlag == 1) {
                      // ����Ѿ������ڻ����У����»�����Ч��
                        int which_url = if_in_cache(url);
                        if (which_url != 0) {
                            Cache[which_url].ttl_end = time(NULL) + CACHE_TTL; // ���»�����Ч��
                        } else {
                            // ����������ڻ����У���ӵ�����
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
                        printf("���ڲ���Դ���ҵ���Ӧip������ͻ��˷�����Ӧ����!\n");

                    //������Ӧ���Ĳ����ظ�client
                    int len;
                    makeUdpMessage(recvBuf, sendBuf, num, recvLen, &len, outputLevel);//ԭ�����ƣ�����ip�����޸ģ�recvBuf����

                    struct header sendHeader;
                    setHeader(&sendHeader, sendBuf);
                    if (outputLevel == twoDebug) {
                        printf("Ҫ���͸��ͻ��˵���Ӧ����:\n");
                        printHeader(&sendHeader);

                        printf("��Ӧԭʼ��Ϣ:\n");
                        printBuf(sendBuf, len);
                    }

                    //������Ӧ����
                    int sendFlag = sendto(mySocket, sendBuf, len, 0, (SOCKADDR*)&clientAddr, clientLen);
                    if (outputLevel == twoDebug) {
                        if (sendFlag == SOCKET_ERROR) {
                            printf("\n(�ڲ���Դ)��ͻ��˷�����Ӧ����ʧ��!\n\n");
                        }
                        else {
                            printf("\n(�ڲ���Դ)��ͻ��˷�����Ӧ���ĳɹ�!\n\n");
                        }
                        puts("===============================================\n\n\n");
                    }
                }

                //�ļ����޼�¼
                else {
                    if (outputLevel == twoDebug) printf("���ڲ���Դ��δ�ҵ���Ӧip�������ⲿDNS���������Ͳ�ѯ����!\n");
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

                    //id_trans�������ڼ�¼idת����ϵ��ÿ��Ԫ�ذ���ԭʼid���ͻ����յ���id���Ƿ��Ѿ���ɡ��Ƿ��յ�dns��������Ӧ���ͻ��˵�clientAddr���յ�dns��������Ӧ��ת������clientAddr

                    //���id_trans����������popǰһ�룬base��Ϊѭ�����е�ƫ������size-baseΪ��ЧԪ�ظ���
                    //�Զ�������sizeΪ1000Ϊ����base���Ե���Ϊ����ѭ����ԭ��popǰ500��Ԫ�أ�������idӦ��501��ʼ��baseӦ����Ϊ500
                    //������500��idӦ��1��ʼ��baseӦ��������Ϊ0�����ÿ������base��0��500֮���л�һ��

                    if (id_trans_size == ID_TRANS_MAX) {
                        for (int i = 0; i < ID_TRANS_MAX / 2; i++) {
                            id_trans[i] = id_trans[i + ID_TRANS_MAX / 2];
                        }
                        base = ID_TRANS_MAX / 2 - base;
                        id_trans_size = ID_TRANS_MAX / 2;
                    }

                    //�����µ�id
                    unsigned short newID = (unsigned short)((base + id_trans_size) % ID_TRANS_MAX);
                    newID = htons(newID);
                    memcpy(recvBuf, &newID, sizeof(unsigned short));//�����ɵ��� ID ���Ƶ���ѯ��Ϣ��ͷ�����滻ԭʼ�� ID
                    //��ӡID
                    if (outputLevel == twoDebug) {
                        printf("IDת������IDΪ%u����IDΪ%u\n", oldID, newID);
                    }

                    id_trans[id_trans_size] = myTransfer;
                    id_trans_size++;

                    int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&DNSAddr, sizeof(DNSAddr));
                    if (outputLevel == twoDebug) {
                        if (sendLen == SOCKET_ERROR) {
                            printf("\n���ⲿDNS���������Ͳ�ѯ����ʧ��!\n\n");
                        }
                        else {
                            printf("\n���ⲿDNS���������Ͳ�ѯ���ĳɹ�!\n\n");
                        }
                        puts("===============================================\n\n\n");
                    }


                }
            }
        }
        else if (myHeader.QR == 1) {//�յ���Ӧ��
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
                            //���յ���IP��ַ��Ϣ��ȡ�������洢��������
                        }
                        // �������Ͷ�Ӧ�� IP ��ַ��ӵ� ipUrlNodeSeq ��
                        if (ipUrlNodeNum < IP_URL_MAX) {
                            ipUrlNodeNum++;
                            strcpy(ipUrlNodeSeq[ipUrlNodeNum].url, url0);
                            memcpy(ipUrlNodeSeq[ipUrlNodeNum].ip, Cache[cache_num].Ip[Cache[cache_num].ip_num].ip, 4);
                            if (outputLevel == twoDebug) {
                                printf("������ %s ���� IP ��ַ %u.%u.%u.%u ��ӵ��ڲ���Դ�б���\n", url0,
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[0],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[1],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[2],
                                    (unsigned char)ipUrlNodeSeq[ipUrlNodeNum].ip[3]);
                            }
                        }
                    }
                    //�������IPv4��Ϣ�����Ըü�¼��ͬʱ�������¼���
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
                printf("IDת������IDΪ%u��", newID);
            }*/
            //ͨ����Ӧ��ϢID�ҵ���ID
            *newID = ntohs(*newID);
            int find = (base + (int)*newID) % ID_TRANS_MAX;
            if (id_trans[find].done == 1) {
                continue;
            }//�ͻ��˵������Ѿ���������Ҫ����Ӧ

            unsigned short oldID = id_trans[find].oldID;
            /*if (outputLevel == twoDebug) {
                printf("��IDΪ%u\n", oldID);
            }*/
            oldID = htons(oldID);
            memcpy(recvBuf, &oldID, sizeof(unsigned short));  //����Ӧ��ϢID�滻�ؿͻ��������е�oldID
            id_trans[find].done = 1;  //���Ϊ�Ѵ���

            //��ӡ
            struct header sendHeader;
            setHeader(&sendHeader, recvBuf);
            if (outputLevel == twoDebug) {
                printf("Ҫ���͸��ͻ��˵���Ӧ����:\n");
                printHeader(&sendHeader);

                printf("��Ӧԭʼ��Ϣ:\n");
                printBuf(recvBuf, recvLen);
            }
            //������Ӧ
            int sendLen = sendto(mySocket, recvBuf, recvLen, 0, (SOCKADDR*)&id_trans[find].clientAddr, sizeof(id_trans[find].clientAddr));
            if (outputLevel == twoDebug) {
                if (sendLen == SOCKET_ERROR) {
                    printf("\n��ͻ��˷�����Ӧ����ʧ��!\n\n");
                }
                else {
                    printf("\n��ͻ��˷�����Ӧ���ĳɹ�!\n\n");
                }
                puts("===============================================\n\n\n");
            }
        }
    }
    //�ر��׽���
    closesocket(mySocket);
    WSACleanup();
}