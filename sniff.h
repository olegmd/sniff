#include <pcap.h>

#define DEFAULT_INTERFACE "eth0"
#define FILTER_LENGH 32
#define MAX_IFACE_LENGTH 16
#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define DATA_FILE "/var/tmp/sniff.log"
#define CONFIG_FILE "/usr/local/etc/sniff.cfg"
#define PID_FILE "/run/sniff.pid"
#define MAX_IFACES 8
#define MAX_COMMAND_LENGTH 64
#define MAX_STAT_FILE_LENGTH 64
#define FULL_LIST "ALL"


/* https://www.tcpdump.org/pcap.html */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

typedef struct { /* to keep the number of packets per interface, store iface name and count in the structure */
    unsigned int count;
    char iface[MAX_IFACE_LENGTH];
} t_iface_c;

struct packet_tree {
    uint32_t ip;
    t_iface_c packets[MAX_IFACES];
    struct packet_tree *left, *right;
};

/* sniff daemon */
void sig_handler(int signo);

int create_pid_file(pid_t pid);

int is_running(void);

int get_iface_addr(char *iface, char *filter_addr, char *errbuf);

int get_iface_name(char *device);

void callback(u_char* iface, const struct pcap_pkthdr* pkthdr, const u_char* packet);

/* sniff CLI */
struct packet_tree *init (char *iface, uint32_t addr);

struct packet_tree *insert (struct packet_tree *ptree, char *iface, uint32_t addr);

void search (struct packet_tree *ptree, uint32_t addr);

void traverse(struct packet_tree *ptree, char *iface);

void traverse_and_free(struct packet_tree *ptree);