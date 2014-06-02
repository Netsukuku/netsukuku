#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "Netsukuku-Console.h"

int fd[2];
pid_t ntkd_pid;

/* this function is run by the second thread */
void *server_opt_pipe(void *args) {

    int i;
    
    int* ServIter = (int*)&server_opt;
    
    for(i = 0; i<33; i++) {
        
        printf("%d\n",*(ServIter + i));
        
    }

}

/*
 * is_ntkd_already_running
 *
 * Returns 1 if there's already a ntkd running
 */
int is_ntkd_already_running(void)
{
	pid_t oldpid;
	FILE *fd;

	if(!(fd=fopen(server_opt.pid_file, "r"))) {
		if(errno != ENOENT)
			printf("Cannot read pid file \"%s\": %s\n",
					server_opt.pid_file, strerror(errno));
		return 0;
	}

	fscanf(fd, "ntkd %d\n", &oldpid);
        if(ferror(fd)) {
		printf("error reading pid file \"%s\": %s\n",
				server_opt.pid_file, strerror(errno));
		fclose(fd);
		return 0;
	}
	fclose(fd);

	return !kill(oldpid, 0);
}

int openpipe(void) {
    
    if(is_ntkd_already_running() == 1){
        char process_name[256] = {0};
        pid_t pid1;
        printf("...Opening Pipe to ntkd...\n");
        FILE *fd1=fopen(server_opt.pid_file, "r");
        while(fscanf(fd1, "%s %d", process_name, &pid1)!=EOF) {
            if(strcmp(process_name, "ntkd") == 0) {
                ntkd_pid = pid1;
                if (pipe(fd) == -1) {
                    printf("Error in Pipe Creation: %s\n", strerror(errno));
                    exit(1);
                }
            }
        }
            fclose(fd1);
    }
    
     else if(is_ntkd_already_running() == 0) {
     printf("ntkd is not running\n ...Exiting...\n");
     exit(0);
     
    }
    
}

int main(void) {
    
    server_opt.pid_file="/var/run/ntkd.pid";
    
    openpipe();
    
    printf("This is the Netsukuku Console, Please type: 'help' for more information.\n");
    
    server_opt_pipe(NULL);
    
/* This variable is our reference to the second thread */
    pthread_t NetsukukuServeroptPipe;

/* create a second thread which executes inc_x(&x) */
    if(pthread_create(&NetsukukuServeroptPipe, NULL, server_opt_pipe, NULL)) {

    fprintf(stderr, "Error creating thread\n");
    return 1;

        }

/* wait for the second thread to finish */
    if(pthread_join(NetsukukuServeroptPipe, NULL)) {

    fprintf(stderr, "Error joining thread\n");
    return 2;

   }

return 0;

}