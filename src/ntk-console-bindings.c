/* Header files required for the console bindings
 * not included outside of this file. */

#include <utmp.h>
#include <sys/un.h>
#include <unistd.h>

#include "netsukuku.h"

/* Constants used for the console bindings. */

#define SERVER_PATH     "/tmp/ntk-console"
#define REQUEST_LENGTH   250
#define FALSE           0

/* Variable and structure defintions, sockfd refers to socket file descriptor
 * length refers to the required length of the requests that will be sent.
 * recv won't wake up until length is received.
 * rc is used for error checking in socket operations.
 * serveraddr is a structure describing the address of 
 * an AF_LOCAL (aka AF_UNIX) socket. */

int sockfd_1 = -1, sockfd_2 = -1;
struct sockaddr_un serveraddr;
int rc, length;

/* Cleans up the console bindings for closing, Closes socket file descriptors,
 * unlinks the server path, etc. */

void clean_up(void) {
    
    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    
    setsockopt(sockfd_1, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
    setsockopt(sockfd_2, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
    
    if (sockfd_1 != -1)
        close(sockfd_1);

    if (sockfd_2 != -1)
        close(sockfd_2);
   
   unlink(SERVER_PATH);
    
}

/* Creates an AF_UNIX socket and binds it to a local address. */

void opensocket(void) {
    
    int stop_trying;
    
    sockfd_1 = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd_1 < 0) {
         perror("socket creation failed");
         exit(-1);
    }
    
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, SERVER_PATH);

    rc = bind(sockfd_1, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr));
    if (rc < 0) {
        perror("bind() failed");
        clean_up();
        if(stop_trying >= 2) {
            perror("bind() failed");
            clean_up();
            opensocket();
            exit(-1);
        }
        stop_trying++;
        opensocket();
    }
}

/* Sends a parsed response to the ntk console client. */

void send_response(char response[REQUEST_LENGTH], ...) {
    int response_length;
    
    response_length = (int)strlen(response);
    memset(response, 'a', REQUEST_LENGTH - response_length);
    rc = send(sockfd_2, response, sizeof(response), 0);
        if (rc < 0){
            perror("send() failed");
            exit(-1);
        }
    
}

void request_cleanup(char unprocessed_request[REQUEST_LENGTH]) {
    
    char remove = 'a';

    char* c;
    int x;
    char* pPosition;
    while(pPosition = strchr(unprocessed_request, 'a') != NULL)  {
        if ((c = index(unprocessed_request, remove)) != NULL) {
        size_t len_left = sizeof(unprocessed_request) - (c+1-unprocessed_request);
        memmove(c, c+1, len_left);
        }
    }
    printf("Cleaned Request is: %s", unprocessed_request);
    
    request_processing(unprocessed_request);
    
}

/* Parses the received request from the ntk console client
 * to data from ntkd structures such as: me 
 * into a response for the ntk console client. */

int request_processing(char unprocessed_request[REQUEST_LENGTH]) {
    
        if(strncmp(unprocessed_request,"uptime", (int)strlen(unprocessed_request))  == 0)
            send_response((char)time(0)-me.uptime);
        
        else if(strncmp(unprocessed_request,"version", (int)strlen(unprocessed_request))  == 0)
            send_response(VERSION_STR);
        
        else if(strncmp(unprocessed_request,"inet_connected", (int)strlen(unprocessed_request))  == 0)
            send_response((char)me.inet_connected);
        
        else if(strncmp(unprocessed_request,"cur_ifs", (int)strlen(unprocessed_request))  == 0)
            send_response((char)me.cur_ifs);
        
        else if(strncmp(unprocessed_request,"cur_ifs_n", (int)strlen(unprocessed_request))  == 0)
            send_response((char)me.cur_ifs_n);
        
        else if(strncmp(unprocessed_request,"cur_qspn_id", (int)strlen(unprocessed_request))  == 0)
            send_response((char)me.cur_qspn_id);
        
        else if(strncmp(unprocessed_request,"cur_ip", (int)strlen(unprocessed_request))  == 0)
            send_response((char)me.cur_ip.data);
        
        /*else if(strncmp(unprocessed_request,"cur_node", (int)strlen(unprocessed_request))  == 0)
            send_response(me.cur_node);
        
        else if(strncmp(unprocessed_request,"ifs", (int)strlen(unprocessed_request))  == 0)
            return 0;
        
        else if(strncmp(unprocessed_request,"ifs_n", (int)strlen(unprocessed_request))  == 0)
            return 0;*/
    send_response(unprocessed_request, " Is invalid or yet to be implemented.");
    return -1;
}

/* Receives a request of 250 bytes from the ntk console client.
 * listen and accept are also in a while loop to allow for different
 * start times between the ntk console bindings and the ntk console client,
 * As well as restarting of the ntk console client. */
void ntkd_request(void) {
    
    char request[REQUEST_LENGTH];
    
    do {
    
        rc = listen(sockfd_1, 10);
            if (rc< 0) {
                perror("listen() failed");
                exit(-1);
            }

        printf("Ready for client connect().\n");
      
        sockfd_2 = accept(sockfd_1, NULL, NULL);
            if (sockfd_2 < 0) {
                perror("accept() failed");
                exit(-1);
            }
            
        length = REQUEST_LENGTH;
        rc = setsockopt(sockfd_2, SOL_SOCKET, SO_RCVLOWAT,
                                          (char *)&length, sizeof(length));
            if (rc < 0) {
                perror("setsockopt(SO_RCVLOWAT) failed");
                exit(-1);
            }
            
        rc = recv(sockfd_2, request, sizeof(request), 0);
            if (rc < 0) {
                perror("recv() failed");
                exit(-1);
            }
            
            printf("%d bytes of data were received\n", rc);
            
                if (rc == 0 || rc < sizeof(request)) {
                    printf("The console client closed the connection before all of the\n");
                    printf("data was sent\n");
                    exit(-1);
                }
        
        request_cleanup(request);  
        } while(FALSE);
        
        clean_up();
        
}