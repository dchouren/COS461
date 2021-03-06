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
#define MAX_NUM_PROCESSES 10 // Maximum number of child processes alive at any time


char *badReqMsg   = "<html><head>\r\b<title>400 Bad Request</title>\r\n"\
              "</head><body>\r\n<h1>Bad Request</h1>\r\n"\
               "</body></html>\r\n";

char *notFoundMsg = "<html><head>\r\b<title>404 Not Found</title>\r\n"\
              "</head><body>\r\n<h1>Not Found</h1>\r\n"\
              "</body></html>\r\n";

char *notImpMsg   = "<html><head>\r\b<title>501 Not Implemented</title>\r\n"\
              "</head><body>\r\n<h1>Not Found</h1>\r\n"\
              "</body></html>\r\n";

int num_child_processes = 0; // Number of currently active child processes 

void sigchld_handler(int s)
{
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0) {
      num_child_processes--; // Update count of child processes
    }

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

/*
 * Load the entire request from new_fd into buf by calling recv() repeatedly 
 * until either 1) recv() throws an error, 2) the client closes the connection,
 * or 3) the buffer contains the request-terminating string "\r\n\r\n". If 
 * successful, returns the number of bytes loaded in to buf. If there is an 
 * error, returns -1.
 */
int recv_request(int sock_fd, char* buf) 
{
  int n_recv; // number of bytes received in one call to recv()
  int n_bytes; // total number of bytes that have been received so far

  n_bytes = 0;

  /* recv() loop */
  while(1) {

    /* Receive data from client and read it in to buffer */    
    n_recv = recv(sock_fd, (buf + n_bytes), (BUFMAX - n_bytes - 1), 0);

    /* recv() returns error */
    if (n_recv == -1) {
      return(-1);
    }
    
    /* Client closes connection */
    if (n_recv == 0){
      break;
    }

    n_bytes += n_recv;

    /* Make buffer null-terminated for strstr call */
    buf[n_bytes] = '\0';

    /* Buffer contains "\r\n\r\n" */
    if (strstr(buf, "\r\n\r\n") != NULL) {
      break;
    }
  } 
  
  return n_bytes;
}


int serve_request(int sock_fd, struct ParsedRequest* req)
{

  // only allow GET requests
  if (strcmp(req->method, "GET") != 0) {
    send(sock_fd, notImpMsg, strlen(notImpMsg), 0);
    return -1;
  }
  
  char* path = malloc(1 + strlen(req->path));
  printf("%s\n", req->path);
  fflush(stdout);
  strcpy(path, req->path);
  printf("%s\n", path);
  fflush(stdout);
  
  // find file type
  char * extension;
  char file_type[10];
  strtok_r(req->path, ".", &extension);

  if (strcmp(extension, "html") == 0 || strcmp(req->path, "/") == 0) {
    strcpy(file_type, "text/html");
  }
  else if (strcmp(extension, "txt") == 0) {
    strcpy(file_type, "text/plain");
  }
  else if (strcmp(extension, "css") == 0) {
    strcpy(file_type, "text/css");
  }
  else if (strcmp(extension, "gif") == 0) {
    strcpy(file_type, "image/gif");
  }
  else if (strcmp(extension, "jpeg") == 0 || strcmp(extension, "jpg") == 0) {
    strcpy(file_type, "image/jpeg");
  }
  else {
    send(sock_fd, badReqMsg, strlen(badReqMsg), 0);
    return -1;
  }


  // now we look for the file
  FILE *file;
  char *buffer;
  int fileLength;

  // Open file 
  // if path is "/" then we want to serve index.html
  if (strcmp(path, "/") == 0) {
    file = fopen("index.html", "rb");
  }
  else {
    file = fopen(path + 1, "r"); // remove open slash
  }
  printf("%s", path + 1);
  fflush(stdout);

  if (!file) {
    if (errno == ENOENT) {  // file not found
      send(sock_fd, notFoundMsg, strlen(notFoundMsg), 0);
    }
    else {
      send(sock_fd, badReqMsg, strlen(badReqMsg), 0);
    }
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


  char header[1024];
  char * status_line = "HTTP/1.0 200 OK";
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

  
  // TODO: write send() loop here
  send(sock_fd, response, responseLength, 0);

  free(buffer);
  free(response);
  free(path);
  
  return 0;
}

/* This is the function called by the child process */
int process_request(sock_fd) 
{
  char buf[BUFMAX]; // Buffer to store incoming data
  int buflen;
  struct ParsedRequest* req; // Stores parsed request data
  
  /* Read request from sock_fd into buffer using recv() */
  if ((buflen = recv_request(sock_fd, buf)) == -1) {
    perror("receiving error");
    return -1;
  }

  printf("server: received: '%s'\n", buf);
  
  /* Create empty ParsedRequest instance */
  req = ParsedRequest_create();
  
  /* Try to parse request in buf; send badReqMsg if request is invalid */
  if (ParsedRequest_parse_server(req, buf, buflen) != 0) {
    send(sock_fd, badReqMsg, strlen(badReqMsg), 0);
    perror("parse failed");
    ParsedRequest_destroy(req);
    return -1;
  }

  /* If parse is successful, print out parsed data */
  printf("Method:%s\n", req->method);
  printf("Protocol:%s\n", req->protocol);
  printf("Host:%s\n", req->host);
  printf("Path:%s\n", req->path);
  printf("Version:%s\n", req->version);

  /* If request is not HTTP/1.0, return error */
  if (strcmp(req->version, "HTTP/1.0") != 0) {
    perror("wrong version");
    ParsedRequest_destroy(req);
    return -1;
  }

  /* Serve request using data in req */
  if (serve_request(sock_fd, req) != 0) {
    perror("error serving request");
    ParsedRequest_destroy(req);
    return -1;
  }
  
  printf("successful process\n");
  /* If we reach this point, processing of request was successful */
  ParsedRequest_destroy(req);
  return 0;
} 
  
int main(int argc, char * argv[])
{

  printf("\n");
  char* port = argv[1]; // Port to listen on
  char s[INET6_ADDRSTRLEN];

  int sockfd; // socket to listen on
  int new_fd;  // socket for new connections

  pid_t frk_val; // return value of fork() function

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
    
    /* Don't accept any new connections if we have too many active
     * chile processes */
    if(num_child_processes > MAX_NUM_PROCESSES)
      continue;

    /* Accept new connection */
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }
    
    /* Is this part necessary?*/
    inet_ntop(their_addr.ss_family,
        get_in_addr((struct sockaddr *)&their_addr),
        s, sizeof s);

    printf("\n\nserver: got connection from %s\n", s);
    fflush(stdout); // (just making sure!)

    /* Spawn new child process */
    frk_val = fork();

    /* Child process */
    if (frk_val == 0) { 
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
    else if (frk_val > 0) {
      num_child_processes++; // increment running count 
      close(new_fd); 
    }
    
    /* Child process failed to spawn */
    else { 
      close(new_fd);
    }
  }
  
  return 0;
}















