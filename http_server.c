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


/* get sockaddr, IPv4 or IPv6: */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* Create the socket the server is going to listen on, and bind it
 * to the given port. If this fails, throw an error and return -1. 
 * This code is almost completely from Beej's Guide to Network 
 * Programming.
 */
int create_listen_socket(char* port) 
{
  const int yes = 1;

  int sockfd;
  int rv;
  
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;
  
  /* Set values in hints */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  /* Use hints to set values in servinfo */
  if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  /* Loop through all the results and bind to the first we can */
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
    return -1;
  }
  
  /* If we reach this point without returning -1, then sockfd 
   * is the file descriptor of a valid socket bound to the 
   * given port */
  return sockfd;
}


int process_request(new_fd) 
{
  
  char buf[BUFMAX]; // Buffer to store incoming data 

  int buflen; // Number of bytes loaded in to buffer

  struct ParsedRequest *req;
  //struct ParsedHeader *header;

  /* Receive data from client and read it in to buffer */
  if ((buflen = recv(new_fd, buf, BUFMAX - 1, 0)) == -1) {
    perror("receiving error");
    return(-1);
  }
  
  printf("server: received: '%s'\n", buf);
  
  req = ParsedRequest_create();
  
  // try to parse and send badreqmsg if bad request
  if (ParsedRequest_parse_server(req, buf, buflen) != 0) {
    // send(new_fd, badReqMsg, strlen(badReqMsg), 0);
    perror("parse failed");
    return -1;
  }

  /* If parse is successful, print out data */
  printf("Method:%s\n", req->method);
  printf("Protocol:%s\n", req->protocol);
  printf("Host:%s\n", req->host);
  printf("Path:%s\n", req->path);
  printf("Version:%s\n", req->version);

  if (strcmp(req->version, "HTTP/1.0") != 0) {
    perror("wrong version");
    ParsedRequest_destroy(req);
    return -1;
  }
  
  // READ FILE
  FILE *file;
  char *buffer;
  int fileLength;
  
  // Open file
  file = fopen(req->path + 1, "rb"); // remove open slash
  if (!file) {
    perror("cant find file");
    return -1;
  }
  
  // Get file length
  fseek(file, 0, SEEK_END);
  fileLength=ftell(file);
  fseek(file, 0, SEEK_SET);
  
  // Allocate memory
  buffer=(char *)malloc(fileLength+1);
  if (!buffer){
    perror("Memory error");
    fclose(file);
    return -1;
  }
  
  // store file in buffer
  fread(buffer, fileLength, 1, file);
  fclose(file);
  
  // TODO: need to figure out what file type
  char header[1000];
  char * file_type;
  char * status_line = "figure out how to get status";
  
  sprintf(header, 
	  "%s\r\n"
	  "Connection: close\r\n"
	  "Content-Length: %i\r\n"
	  "Content-Type: %s\r\n"
	  "\r\n", status_line, fileLength, file_type);
  
  int responseLength = fileLength + strlen(header);
  
  // create response from header and file
  char * response = (char*)malloc(responseLength);
  strcpy(response, header);
  memcpy(response+strlen(header), buffer, fileLength);
  
  // send header and file through HTTP
  send(new_fd, response, responseLength, 0);
  
  printf("here");
  
  /* Call destroy on any ParsedRequests that you create 
   * once you are done using them. This will free memory 
   * dynamically allocated by the proxy_parse library. */
  ParsedRequest_destroy(req);
  
  /* Return success status */
  return 0;
} 
 
	
int main(int argc, char * argv[])
{

  char* port = argv[1]; // Port to listen on
  char s[INET6_ADDRSTRLEN];

  int sockfd; // socket to listen on
  int new_fd;  // socket for new connections

  struct sigaction sa;

  /* Connector's address information */
  struct sockaddr_storage their_addr; 
  socklen_t sin_size = sizeof their_addr;

  /* Create socket on specified port to listen on */
  sockfd = create_listen_socket(port);
  
  /* Listen for incoming connections */
  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  /* Reap all dead processes */
  sa.sa_handler = sigchld_handler; 
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }
  
  printf("server: waiting for connections...\n");

  /* Main accept() loop */  
  while(1) {  
    
    /* Accept new connection */
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }
    
    inet_ntop(their_addr.ss_family,
	      get_in_addr((struct sockaddr *)&their_addr),
	      s, sizeof s);

    printf("server: got connection from %s\n", s);
    fflush(stdout); // (just making sure!)

    /* Child process */
    if (fork() == 0) { 

      /* Close listener socket -- child doesn't need this */
      close(sockfd);
      
      /* Call process_request method */
      if (process_request(new_fd) == -1) {
	perror("Error processing request");	
	close(new_fd);
	exit(EXIT_FAILURE);
      }

      /* Close new_fd and exit with success status */
      close(new_fd);
      exit(EXIT_SUCCESS);
    }

    /* Parent process */
    else { 
      /* Close new_fd and return to beginning of loop */
      close(new_fd); 
    }
  }
  
  return 0;
}















