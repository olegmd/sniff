#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include "sniff.h"


int
main (int argc, char *argv[]) {
    char iface[MAX_IFACE_LENGTH];
    char iface_opt[MAX_IFACE_LENGTH] = DEFAULT_INTERFACE;
    char str_addr[INET_ADDRSTRLEN];
    char line[MAX_STAT_FILE_LENGTH];
    FILE *file;
    struct packet_tree *tree_ptr = NULL;
    unsigned int ip;
    int res_scan = 0;
    short int is_tree = 0; /*check if we have a binary tree or need to make/re-make it*/
    struct sockaddr_in sa;
    char cmd[MAX_COMMAND_LENGTH];


    for (;;) {

        if (is_tree == 0) {
            printf(">> Loading Data...\n");
            file = fopen(DATA_FILE,"r");

            if (file == NULL) {
                printf(">> Could not open file, %s!", DATA_FILE);
                continue;
            }

            while (fgets(line, MAX_STAT_FILE_LENGTH, file) != NULL) {
                res_scan = sscanf(line, "%s %d;", iface, &ip);
                if (res_scan < 2) {
                    printf(">> Skiped broken line\n");
                    continue;
                }
                tree_ptr = insert(tree_ptr, iface, ip);
            }
            fclose(file);
            is_tree = 1;
        }
    
        printf("> ");
        fgets(cmd, MAX_COMMAND_LENGTH, stdin);

        if (strcmp("stop\n", cmd) == 0) { /* STOP the capture */
        int res;
            if (is_running() < 1) {
                printf(">> The capture is not running\n");
                continue;
            }

            res = kill((pid_t)is_running(), SIGUSR1);
            if (res == 0) {
                printf(">> Stopped\n");
            } else {
                printf(">> Still running, please use ROOT permissions\n");
            }
        } 


        else if (strcmp("start\n", cmd) == 0) { /* START the capture */
            if (is_running() > 1) {
                printf(">> The capture is already running\n");
                continue;
            }

            system("./sniff");
        }  


        else if (strncmp("select iface ", cmd, 13) == 0) { /* SELECT iface [iface] */
            file = fopen(CONFIG_FILE, "w");
            if (file == NULL) {
                printf(">> Could not open the config file: %s\n", CONFIG_FILE);
                continue;
            }

            res_scan = sscanf(cmd, "select iface %16s", iface_opt);
            if (res_scan != 1) {
                printf(">> Could not parse the option\n");
                continue;
            }

            fprintf(file, "iface:%s", iface_opt);
            fclose(file);
            printf(">> Changed the default iface to %s\n", iface_opt);

        }  


        else if (strncmp("show ", cmd, 5) == 0) {                                  /* SHOW [ip] count */
            res_scan = sscanf(cmd, "show %16s", str_addr);
            if (res_scan != 1) {
                printf(">> Could not parse the option\n");
                continue;
            }

            inet_pton(AF_INET, str_addr, &(sa.sin_addr));
            search(tree_ptr, sa.sin_addr.s_addr);
            sa.sin_addr.s_addr = 0;
        } 


        else if (strncmp("stat\n", cmd, 5) == 0 || strncmp("stat ", cmd, 5) == 0) { /* STAT iface [iface] */
            if (strncmp("stat\n", cmd, 5) == 0) {
                traverse(tree_ptr, FULL_LIST);
            } else {
                res_scan = sscanf(cmd, "stat %16s", iface_opt);
                if (res_scan != 1) {
                    printf(">> Could not parse the option\n");
                    continue;
                }
                traverse(tree_ptr, iface_opt);
            }
            
        }


        else if (strcmp("refresh\n", cmd) == 0) { /* REFRESH stat info */
            if (is_tree == 1) {
                traverse_and_free(tree_ptr);
                tree_ptr = NULL;
                is_tree = 0;
            }
        } 


        else if (strcmp("exit\n", cmd) == 0) {
            if (is_tree == 1) {
                traverse_and_free(tree_ptr);
            }
            
            printf(">> Bye!\n");
            return 0;
        } 


        else if (strcmp("--help\n", cmd) == 0 || strcmp ("?\n", cmd) == 0) {
            printf (">> Usage:\n"
                    "start\t\t-\tstart the capture\n"
                    "stop\t\t-\tstop the capture\n"
                    "refresh\t\t-\tre-read the caputre file\n"
                    "select iface <iface> -\tselect iface for a new capture\n"
                    "show <ip> count\t-\t​print number of packets received from IP address\n"
                    "stat​ <iface>​\t-\t​show all collected statistics for the particular interface\n"
                    "\t\t\tif <iface> is omitted - for all interfaces\n"
                    "--help​ | ? ​(show this info)\n"
                   );
        } 


        else if (strcmp("\n", cmd) == 0) {
            ;
        }

        else {
            printf(">> Command not found. Type --help or ? to get usage info\n");
        }
    }

    return 0;
}


struct packet_tree
*init (char *iface, unsigned int addr) {
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
*insert (struct packet_tree *ptree, char *iface, unsigned int addr) {
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
search (struct packet_tree *ptree, unsigned int addr) {
    if (ptree == NULL) {
        printf(">> No packets found \n");
        return;
    }
    if (addr == 0) {
        printf(">> Does not look like IP \n");
        return;
    }
    if (ptree->ip == addr) {
        printf(">> Total packets->\n");
        for (int i=0; i < MAX_IFACES; i++){
            if (ptree->packets[i].count != 0) {
                printf("%16s: %u  \n",ptree->packets[i].iface, ptree->packets[i].count);
            }
        }
    } else if (ptree->ip > addr) {
        search (ptree->right, addr);
    } else if (ptree->ip < addr) {
        search (ptree->left, addr);
    }
    return;
}

void 
traverse(struct packet_tree *ptree, char *iface) {
    char str_addr[INET_ADDRSTRLEN];
    if (ptree == NULL)
        return;
    traverse(ptree->left, iface);
    traverse(ptree->right, iface);
    inet_ntop(AF_INET, &ptree->ip, str_addr, INET_ADDRSTRLEN);
    /*printf("%s \n",str_addr);*/
    for (int i=0; i < MAX_IFACES; i++){
        if (ptree->packets[i].count != 0 \
        && (strcmp(iface, FULL_LIST) == 0 \
        || strcmp(iface, ptree->packets[i].iface) == 0)) {
            printf("%15s %10s: packets: %u \n",str_addr, ptree->packets[i].iface, ptree->packets[i].count);
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