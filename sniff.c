#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include "sniff.h"


pcap_t *handle;
pthread_mutex_t lock;
pthread_mutex_t lock_d; /*dump_log*/
volatile int running = 1;
volatile int configured = 0; /* prepare_capture if 0 */
char iface_g[MAX_IFACE_LENGTH] = ""; /* iface from `set iface` */


int
main() {

    pid_t pid = 0, sid = 0;
    pthread_t capture_tid, listener_tid;

    int sockfd, newsockfd, clilen;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ERROR opening socket \n");
        return 1; 
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SOCK_ADDR);
    serv_addr.sin_port = htons(DEFAULT_PORT);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("ERROR on binding \n");
        return 1;
    }
    
    /*Daemonize*/

    pid = fork();

    if (pid < 0) {
        return 1;
    } else if (pid > 0) {
        printf("Child pid is %i\n", pid);
        return 0;
    }

    umask(0);
    sid = setsid();

    if(sid < 0) {
        return 1;
    }

    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    pthread_create(&listener_tid, NULL, listener, (void *) &sockfd);  
    pthread_create(&capture_tid, NULL, capture_loop, NULL);
    pthread_join(listener_tid, NULL);
    pthread_join(capture_tid, NULL);

    return 0;
}


int
get_iface_addr(char *iface, char *filter_addr, char *errbuf) {
    pcap_if_t *alldevsp;

    if (pcap_findalldevs(&alldevsp, errbuf) != 0) {
        return -1;
    }

    for (alldevsp; alldevsp != NULL; alldevsp = alldevsp->next) {
        if (strcmp(alldevsp->name, iface) != 0) {
            continue;
        }
        for (pcap_addr_t *adrs = alldevsp->addresses; adrs != NULL; adrs = adrs->next) {
            if (adrs->addr->sa_family == AF_INET) {
                strcpy(filter_addr,inet_ntoa(((struct sockaddr_in*)adrs->addr)->sin_addr));
                return 1; /* return the first address found */
            }
        }
    }
    pcap_freealldevs(alldevsp);
    return 0;
}

void
callback(u_char* iface, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct sniff_ip *ip;                       /* The IP header */
    int size_ip;
    FILE *file;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); /* cast struct ip from u_char packet */
    size_ip = IP_HL(ip)*4;

    if (size_ip < 20 || size_ip > 60) {
        return;
    }

    file = fopen(DATA_FILE, "a");
    if (file == NULL) {
        return;
    }

    fprintf(file, "%s %u; \n", iface, ip->ip_src.s_addr);
    fclose(file);
    return;
}

void
*capture_loop (void *args) {
    char errbuf[PCAP_ERRBUF_SIZE], device[MAX_IFACE_LENGTH] = DEFAULT_INTERFACE;   /* Error buffer and device name */
    pthread_mutex_lock(&lock_d);
    dump_log("capture loop started");
    pthread_mutex_unlock(&lock_d);
    while (1) {
        pthread_mutex_lock(&lock);
        if (configured == 0) {
            if (strlen(iface_g) > 0) {
                strcpy(device, iface_g);
            }
            configured = prepare_capture(device);
            pthread_mutex_unlock(&lock);
        } else {
            pthread_mutex_unlock(&lock);
        }

        pthread_mutex_lock(&lock);
        if (running == 1 && configured == 1) { /* if prepare_capture was successful: enter the pcap_loop */
            pthread_mutex_unlock(&lock);
            pcap_loop(handle, -1, callback, device);
        } else {
            pthread_mutex_unlock(&lock);
        }

        sleep(1);
    }
}

void
*listener (void *args) {
    int sockfd, newsockfd, clilen;
    char buffer[BUFFER];
    char msg[MSG];
    struct sockaddr_in cli_addr, sa;
    char iface_opt[MAX_IFACE_LENGTH];
    char str_addr[INET_ADDRSTRLEN];
    struct packet_tree *tree_ptr = NULL;
    int res_scan = 0;
    int n = 0;

    sockfd = *((int *) args);

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {                     /* main loop */
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
              pthread_mutex_lock(&lock_d);
              dump_log("listener: ERROR on accept");
              pthread_mutex_unlock(&lock_d);
              continue;
        }
        bzero(buffer, BUFFER);
        n = read(newsockfd, buffer, 255);
        if (n < 0) {
            pthread_mutex_lock(&lock_d);
            dump_log("listener: ERROR reading from socket");
            pthread_mutex_unlock(&lock_d);
            continue;
        }

        if (strncmp(buffer, "start", 5) == 0) {
            pthread_mutex_lock(&lock);
            if (running > 0) {
                strcpy(msg, "The capture is already running");
            } else {
                running++;
                configured = 0;
                strcpy(msg, "Starting the capture");
            }
            pthread_mutex_unlock(&lock);
        } else

        if (strncmp(buffer, "stop", 4) == 0) { /* STOP THE CAPTURE */
            pthread_mutex_lock(&lock);
            if (running > 0) {
                strcpy(msg, "Stopping the capture");
                pcap_breakloop(handle);
                running = 0;
            } else {
                strcpy(msg, "Nothing to stop");
            }
            pthread_mutex_unlock(&lock);
        } else
        
        if (strncmp(buffer, "select iface ", 13) == 0) { /* SELECT IFACE */
            res_scan = sscanf(buffer, "select iface %16s", iface_opt);
            if (res_scan != 1) {
                strcpy(msg, "Could not parse the option");
            } else {
                pthread_mutex_lock(&lock);
                strcpy(iface_g, iface_opt);
                configured = 0;
                pthread_mutex_unlock(&lock);
                strcpy(msg, "in the next capture iface will be updated to");
                strcat(msg, iface_opt);
            }
        } else

        if (strncmp(buffer, "show ", 5) == 0) { /* SHOW [IP] COUNT */
            res_scan = sscanf(buffer, "show %16s", str_addr);
            if (res_scan != 1) {
                pthread_mutex_lock(&lock_d);
                dump_log("listener: could not parse the option");
                pthread_mutex_unlock(&lock_d);
            } else {
                tree_ptr = read_tree_from_file();
                inet_pton(AF_INET, str_addr, &(sa.sin_addr));
                search(tree_ptr, sa.sin_addr.s_addr, msg);
                sa.sin_addr.s_addr = 0;
            }
        } else

        if (strncmp(buffer, "stat", 4) == 0 || strncmp(buffer, "stat ", 5) == 0) { /* STAT [IFACE] IFACE */
            tree_ptr = read_tree_from_file();
            if (strncmp(buffer, "stat ", 5) == 0) {
                res_scan = sscanf(buffer, "stat %16s", iface_opt);
                if (res_scan != 1) {
                    strcpy(msg, "Could not parse the option");
                } else {
                    traverse(tree_ptr, iface_opt, msg);
                }
            } else {
                traverse(tree_ptr, FULL_LIST, msg);
            }
        } else {
            strcpy(msg, "Unrecognized option");
        }

        n = write(newsockfd, msg, strlen(msg));
        if (n < 0) {
            pthread_mutex_lock(&lock_d);
            dump_log("listener: ERROR writing to socket");
            pthread_mutex_unlock(&lock_d);
        }
        close(newsockfd);
        memset(msg, 0, sizeof msg);
        traverse_and_free(tree_ptr);
        tree_ptr = NULL;
        sleep(1);
    }
}

int 
prepare_capture (char *device) { /* prepare filters and handle, return 1 on success */
    char filter_exp[FILTER_LENGH] = "dst host ";     /* The filter expression */ 
    char filter_addr[INET_ADDRSTRLEN];   /* IP of the interface. Will be concatenated with filter_exp*/
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;   /* The compiled filter expression */
    bpf_u_int32 mask;        /* The netmask of our sniffing device */
    bpf_u_int32 net;         /* The IP of our sniffing device */
    memset(filter_addr, 0, INET_ADDRSTRLEN);

    if (get_iface_addr(device, filter_addr, errbuf) != 1) {
        pthread_mutex_lock(&lock_d);
        dump_log("capture: Could not get IP address of the interface");
        pthread_mutex_unlock(&lock_d);
        return 0;
    }
            
    strcat(filter_exp, filter_addr);
        
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
        
    if (handle == NULL) {
        pthread_mutex_lock(&lock_d);
        dump_log("capture: Couldn't open device");
        pthread_mutex_unlock(&lock_d);
        return 0;
    }
    
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) { /*get netmask for the filter*/
        pthread_mutex_lock(&lock_d);
        dump_log("capture: Can't get netmask for device");
        pthread_mutex_unlock(&lock_d);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) { /*compilling the filter filter_exp*/
        pthread_mutex_lock(&lock_d);
        dump_log("capture: Couldn't parse filter");
        pthread_mutex_unlock(&lock_d);
        return 0;
    }
            
    if (pcap_setfilter(handle, &fp) == -1) {
        pthread_mutex_lock(&lock_d);
        dump_log("capture: Couldn't install filter");
        pthread_mutex_unlock(&lock_d);
        return 0;
    }
    return 1;
}

struct packet_tree
*init (char *iface, uint32_t addr) {
    struct packet_tree *new_tree = (struct packet_tree *)malloc(sizeof(struct packet_tree));
    new_tree->ip = addr;
    new_tree->packets[0].count = 1; /* add the counter of packets and name of the interface that received them */
    strcpy(new_tree->packets[0].iface, iface);
    for (int i = 1; i < MAX_IFACES; i++) {
        new_tree->packets[i].count = 0;
    }
    new_tree->left = new_tree->right = NULL;
    return new_tree;
}

struct packet_tree
*insert (struct packet_tree *ptree, char *iface, uint32_t addr) {
    if (ptree == NULL) {
        ptree = init(iface, addr);
    } else if (ptree->ip == addr) {
        for (int i=0; i < MAX_IFACES; i++){
            if (strcmp(ptree->packets[i].iface, iface) == 0) {
                ptree->packets[i].count++;
                break;
            }
            else if (ptree->packets[i].count == 0) {
                /* add the counter of packets and name of the NEW interface that received them */
                strcpy(ptree->packets[i].iface, iface);
                ptree->packets[i].count = 1;
                break;   
            }
        }
    } else if (ptree->ip > addr) {
        ptree->right = insert(ptree->right, iface, addr);
    } else if (ptree->ip < addr) {
        ptree->left = insert(ptree->left, iface, addr);
    }
    return ptree;
}

void
search (struct packet_tree *ptree, uint32_t addr, char *buffer) {
    char tmp[BUFFER];
    if (ptree == NULL) {
        return;
    }
    if (addr == 0) {
        return;
    }
    if (ptree->ip == addr) {
        for (int i=0; i < MAX_IFACES; i++){
            if (ptree->packets[i].count != 0) {
                sprintf(tmp, "%16s: %u  \n", ptree->packets[i].iface, ptree->packets[i].count);
                strcat(buffer, tmp);
            }
        }
    } else if (ptree->ip > addr) {
        search (ptree->right, addr, buffer);
    } else if (ptree->ip < addr) {
        search (ptree->left, addr, buffer);
    }
    return;
}

void 
traverse(struct packet_tree *ptree, char *iface, char *buffer) {
    char tmp[BUFFER];
    char str_addr[INET_ADDRSTRLEN];
    if (ptree == NULL)
        return;
    traverse(ptree->left, iface, buffer);
    traverse(ptree->right, iface, buffer);
    inet_ntop(AF_INET, &ptree->ip, str_addr, INET_ADDRSTRLEN);

    for (int i=0; i < MAX_IFACES; i++){
        if (ptree->packets[i].count != 0 \
        && (strcmp(iface, FULL_LIST) == 0 \
        || strcmp(iface, ptree->packets[i].iface) == 0)) {
            sprintf(tmp, "%15s %10s: packets: %u \n", str_addr, ptree->packets[i].iface, ptree->packets[i].count);
            strcat(buffer, tmp);
        }
    }
}

void
traverse_and_free(struct packet_tree *ptree) {
    if (ptree == NULL)
        return;
    traverse_and_free(ptree->left);
    traverse_and_free(ptree->right);
    free(ptree);
}

struct packet_tree
*read_tree_from_file () {
    struct packet_tree *tree_ptr = NULL;
    char iface[MAX_IFACE_LENGTH];
    uint32_t ip;
    FILE *file;
    int res_scan = 0;
    char line[MAX_STAT_FILE_LENGTH];

    file = fopen(DATA_FILE,"r");
    if (file == NULL) {
        return NULL;
    }

    while (fgets(line, MAX_STAT_FILE_LENGTH, file) != NULL) {
        res_scan = sscanf(line, "%s %u;", iface, &ip);
        if (res_scan < 2) {
            continue;
        }
        tree_ptr = insert(tree_ptr, iface, ip);
    }
    fclose(file);
    return tree_ptr;
}

void dump_log(char *message) {
    time_t rawtime;
    struct tm *info;
    char buffer[80];

    FILE *file;
    file = fopen(LOG_FILE, "a+");
    if (file == NULL) {
        return;
    } 
    
    time( &rawtime );
    info = localtime( &rawtime );
    strftime(buffer,80,"%x - %I:%M%p", info);

    fprintf(file,"|%s|", buffer );
    fprintf(file, "%s\n", message);
    fclose(file);
    return;
}
