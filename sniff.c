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
#include <signal.h>
#include "sniff.h"


pcap_t *handle; 


int
main() {
    char errbuf[PCAP_ERRBUF_SIZE], device[MAX_IFACE_LENGTH];     /* Error buffer and device name */
    char filter_exp[FILTER_LENGH] = "dst host ";                 /* The filter expression */
    char filter_addr[INET_ADDRSTRLEN];   /* IP of the interface. Will be concatenated with filter_exp*/
    struct bpf_program fp;   /* The compiled filter expression */
    bpf_u_int32 mask;        /* The netmask of our sniffing device */
    bpf_u_int32 net;         /* The IP of our sniffing device */
    pid_t pid = 0, sid = 0;

    if (is_running() > 0) {
        printf(">>>> The capture is already running \n");
        return 1;
    }

    if (get_iface_name(device) == 0) {
        strcpy(device, DEFAULT_INTERFACE);
    }
        printf(">>>> Device: %s\n", device);

    if (get_iface_addr(device, filter_addr, errbuf) != 1) {
        printf(">>>> Could not get IP address of the interface\n");
        return 1;
    }

    strcat(filter_exp, filter_addr);
    /*printf(">>>> Filter: %s\n", filter_exp);*/
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);

    if (handle == NULL) {
        printf(">>>> Couldn't open device: %s\n", errbuf);
        return 1;
    }
    
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) { /*get netmask for the filter*/
        printf(">>>> Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) { /*compilling the filter filter_exp*/
        printf(">>>> Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
         printf(">>>> Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
         return 1;
    }

    if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
        printf(">>>> Can't catch SIGUSR1 \n");
    }
    
    /*Daemonize*/
    
    pid = fork();

    if (pid < 0) {
        return 1;
    } else if (pid > 0) {
        printf(">>>> Child pid is %i\n", pid);
        create_pid_file(pid);
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

    pcap_loop(handle, -1, callback, device);

    return 0;
}


void
sig_handler(int signo) {
    if (signo == SIGUSR1) {
        pcap_breakloop(handle);
        pcap_close(handle);
        unlink(PID_FILE);
    }
}

int
create_pid_file(pid_t pid) {
    FILE *file;
    file = fopen(PID_FILE, "w");
    if (file == NULL) {
        printf(">>>> Cannot create pid file!\n");
        return 0;
    }
    fprintf(file, "%i", pid);
    fclose(file);
    return 1;
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

int
get_iface_name(char *device) {
    FILE *file;
    int result = 0;
    file = fopen(CONFIG_FILE, "r");
    if (file == NULL) {
        return 0;
    }
    result = fscanf(file, "iface:%s ", device);
    fclose(file);
    if (result == 1) {
        return 1;
    } else {
        device = NULL;
        return 0;
    }
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
