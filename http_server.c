#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "proxy_parse.h"

//gcc http_server.c proxy_parse.c -o http_server;./http_server


#define BACKLOG 10     // how many pending connections queue will hold
#define BUFMAX 4096   // max number of bytes we can hold (4kb)


char *badReqMsg   = "<html><head>\r\b<title>400 Bad Request</title>\r\n"\
	            "</head><body>\r\n<h1>Bad Request</h1>\r\n"\
	             "</body></html>\r\n";

char *notFoundMsg = "<html><head>\r\b<title>404 Not Found</title>\r\n"\
	            "</head><body>\r\n<h1>Not Found</h1>\r\n"\
	            "</body></html>\r\n";

char *notImpMsg   = "<html><head>\r\b<title>501 Not Implemented</title>\r\n"\
	            "</head><body>\r\n<h1>Not Found</h1>\r\n"\
	            "</body></html>\r\n";

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
	
int main(int argc, char * argv[])
{

    char* port = argv[1];

    char buf[BUFMAX];   // use this to read stuff

    struct ParsedRequest *req;
    struct ParsedHeader *header;
    FILE *filep;
    long fsize;
    char *version;
    int numbytes;

    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector"s address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;

    char s[INET6_ADDRSTRLEN];
    int rv;

    int length;

    char response[BUFMAX];   // holds our response

    // from beej
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    // from beej
    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }


    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            // close(sockfd); // child doesn"t need the listener
            if ((numbytes = recv(new_fd, buf, BUFMAX-1, 0)) == -1) {
                 perror("receiving error");
                 exit(1);
               }

            printf("server: received: '%s'\n", buf);


            printf("Method:%s\n", req->method);
            printf("Protocol:%s\n", req->protocol);
            printf("Host:%s\n", req->host);
            printf("Path:%s\n", req->path);
            printf("Version:%s\n", req->version);

            req = ParsedRequest_create();

            // try to parse and send badreqmsg if bad request
            if (ParsedRequest_parse(req, buf, length) != 0) {
                // send(new_fd, badReqMsg, strlen(badReqMsg), 0);
                perror("parse failed");
                return -1;
            }
            if (strcmp(req->version, "HTTP/1.0") != 0) {
                perror("wrong version");
                ParsedRequest_destroy(req);
                close(new_fd);
                exit(1);
            }

            // READ FILE
            FILE *file;
            char *buffer;
            int fileLength;

            //Open file
            file = fopen(req->path + 1, "rb"); // remove open slash
            if (!file)
            {
                printf("cant find file");
                exit(1);
            }

            //Get file length
            fseek(file, 0, SEEK_END);
            fileLength=ftell(file);
            fseek(file, 0, SEEK_SET);

            //Allocate memory
            buffer=(char *)malloc(fileLength+1);
            if (!buffer)
            {
                fprintf(stderr, "Memory error");
                fclose(file);
                exit(1);
            }

            // store file in buffer
            fread(buffer, fileLength, 1, file);
            fclose(file);

            // TODO: need to figure out what file type
            char header[1000];
            char * file_type;

            sprintf(header, 
            "%s\r\n"
            "Connection: close\r\n"
            "Content-Length: %i\r\n"
            "Content-Type: %s\r\n"
            "\r\n", status_line, fileLen, file_type);

            responseLength = fileLength + strlen(header);

            // create response from header and file
            char * response = (char*)malloc(responseLength);
            strcpy(response, header);
            memcpy(response+strlen(header), buffer, fileLength);

            // send header and file through HTTP
            send(new_fd, response, responseLength, 0);

            printf("here");

            // Call destroy on any ParsedRequests that you
            // create once you are done using them. This will
            // free memory dynamically allocated by the proxy_parse library. 
            ParsedRequest_destroy(req);
            close(new_fd);
            exit(0);

            // close(sockdf);

            // if (send(new_fd, "Hello, world!", 13, 0) == -1)
            //     perror("send");
            // close(new_fd);
            // exit(0);
        }
        close(new_fd);  // parent doesn"t need this
    }

	return 0;
}















