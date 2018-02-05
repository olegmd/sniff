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
   time_t rawtime;
   struct tm *info;
   char buffer[80];
   time( &rawtime );

   info = localtime( &rawtime );

   strftime(buffer,80,"%x - %I:%M%p", info);
   printf("Formatted date & time : |%s|\n", buffer );
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