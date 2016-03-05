package main

import (
    "fmt"
    "os"
    "net"
    "net/http"
    "bufio"
    "io"
    "bytes"
    "strings"
)

const EXIT_FAILURE = 1

func usage() {
    fmt.Println("Usage: proxy <port-number>")
    os.Exit(EXIT_FAILURE)
}


func send_500_status(conn net.Conn) {

    response_line := "HTTP/1.0 500 Internal Server Error\r\n"
    header := "Connection: closed\r\n\r\n"
    conn.Write([]byte(response_line + header))

}



func handleConnection(cn_client net.Conn) {

    defer cn_client.Close()
    
    /* Parse request from client connection */
    request, err := http.ReadRequest(bufio.NewReader(cn_client))
    if err != nil {
        send_500_status(cn_client)
        return
    }

    if request.Method != "GET" {
        send_500_status(cn_client)
        return        
    }
    
    /* Parse destination host string from request */
    host := request.URL.Host

    /* If host string doesn't contain port, set port to 80 */
    if (!strings.Contains(host, ":")) {
        host += ":80"
    }
   
    /* Connect to server */   
    cn_server, err := net.Dial("tcp", host)
    if err != nil {
        send_500_status(cn_client)
        return
    }

    defer cn_server.Close()

    /* Parse requested path from request */
    path := request.URL.Path

    /* Send request line to server */
    _, err = cn_server.Write([]byte("GET " + path + " HTTP/1.0\r\n"))
    if err != nil {
        send_500_status(cn_client)
        fmt.Println(err)
        return
    }
    
    /* Modify headers from request and send to server */
    request.Header.Set("Connection", "close")
    request.Header.Set("Host", host)
    request.Header.Write(cn_server)

    /* Send terminating 4 bytes to server */
    cn_server.Write([]byte("\r\n\r\n"))

    /* Read response from server into buffer */
    var buf bytes.Buffer
    io.Copy(&buf, cn_server)

    /* Send response from server to client */
    buf.WriteTo(cn_client)
}

func main() {

    if len(os.Args) != 2 {
        usage()
    }


    /* Format port string */
    var port string = ":" + os.Args[1]

    /* Create Listener */
    ln, err := net.Listen("tcp", port)
    if err != nil {
        panic(err)
    }

    /* Accept loop */
    for {

        /* Accept new connection */
        conn, err := ln.Accept()
        if err != nil {
            panic(err)
        }

        /* Spawn goroutine to handle connection */
        go handleConnection(conn)
    }
}
 



