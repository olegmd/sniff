/* 
Check if sniff is currently running:
return PID from the file if exists, otherwise 
return 0

Is used by both daemon & CLI
*/
#include <stdlib.h>
#include <stdio.h>
#define PID_FILE "/run/sniff.pid"

int
is_running(void) {
	char line[8];
    int pid = 0;
    FILE *file;
    file = fopen(PID_FILE, "r");
    if (file == NULL) {
        return 0;
    } else {
    	fgets(line, 8, file);
        sscanf(line, "%i ", &pid);
        fclose(file);
        return pid;
    }
}