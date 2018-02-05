#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "sniff.h"

int
main(int argc, char *argv[])
{
    int sockfd, n;
    struct sockaddr_in serv_addr;
    char buffer[MSG]; /* it is gonna be big */
    char cmd[BUFFER];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("printf opening socket");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SOCK_ADDR);
    serv_addr.sin_port = htons(DEFAULT_PORT);

    if (connect(sockfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("ERROR connecting to daemon\n");
            if (argc == 2 && strcmp(argv[1], "start") == 0) {
                printf("Trying to start the daemon\n");
                system("./sniff");
            }
        return 0;
    }
    
    bzero(buffer, MSG);

    if (argc == 2) {                                       /* START / STOP / STAT */
        if (strcmp(argv[1], "start") == 0\
        || strcmp(argv[1], "stop") == 0\
        || strcmp(argv[1], "stat") == 0) {
            n = write(sockfd, argv[1], strlen(argv[1]));
        } else {
            print_help();
            return 1;
        }

    } else 

    if (argc == 3) {                                       /* STAT IFACE <iface>*/
        if (strcmp(argv[1], "stat") == 0) {
            for (int i = 1; i < argc; i++) {
                strcat(cmd, argv[i]);
                strcat(cmd, " ");
            }
            n = write(sockfd, cmd, strlen(cmd));
        } else {
            print_help();
            return 1;
        }

    } else

    if (argc == 4) {                                       /* SHOW [IP] COUNT / SELECT IFACE [IFACE]*/
        if ((strcmp(argv[1], "show") == 0 && strcmp(argv[3], "count") == 0)\
        || (strcmp(argv[1], "select") == 0 && strcmp(argv[2], "iface") == 0)) {
            for (int i = 1; i < argc; i++) {
                strcat(cmd, argv[i]);
                strcat(cmd, " ");
            }
        n = write(sockfd, cmd, strlen(cmd));
        }
        else {
            print_help();
            return 1;
        }
    } else {
        print_help();
        return 1;
    }

    n = read(sockfd, buffer, MSG);
    if (n < 0) {
        printf("ERROR reading from socket \n");
    }
    
    printf("%s\n",buffer);

    return 0;
}

void print_help () {
    printf ("\nUsage:\n"
        "start\t\t-\tstart the capture\n"
        "stop\t\t-\tstop the capture\n"
        "select iface <iface> -\tselect iface for a new capture\n"
        "show <ip> count\t-\t​print number of packets received from IP address\n"
        "stat​ <iface>​\t-\t​show all collected statistics for the particular interface\n"
        "\t\t\tif <iface> is omitted - for all interfaces\n"
        "--help​ | ? ​(show this info)\n"
       );
}
