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


func handleConnection(old_conn net.Conn) {

    println("here")

    defer old_conn.Close()

    // read request
    request, error := http.ReadRequest(bufio.NewReader(old_conn))
    if error != nil {
        // TODO: send 400 error
        println("read request error")
        fmt.Println(error)
        os.Exit(1)
    }
    if request.Method != "GET" {
        // TODO: send 501 error
        println("not get error")
        os.Exit(1)
    }
    url := request.URL
    path := url.Path
    host := request.URL.Host

    if (!strings.Contains(host, ":")) {
        host += ":80"
    }

    // open connection
    new_conn, error := net.Dial("tcp", host)
    if error != nil {
        // handle error
        println("new connection error")
        os.Exit(1)
    }
    defer new_conn.Close()

    //send new request
    // var get_buffer bytes.Buffer
    // get_buffer.WriteString("GET ")
    // get_buffer.WriteString(path)
    // get_buffer.WriteString(" HTTP/1.0\r\n")
    new_conn.Write([]byte("GET " + path + " HTTP/1.0\r\n"))
    request.Header.Set("Connection", "close")
    request.Header.Set("Host", host)

    request.Header.Write(new_conn)
    new_conn.Write([]byte("\r\n\r\n"))

    // read response
    var buf bytes.Buffer
    io.Copy(&buf, new_conn)
    buf.WriteTo(old_conn)

}

func main() {
    if len(os.Args) != 2 {
        usage()
    }
    var port string = ":" + os.Args[1]

    tcp_address, err := net.ResolveTCPAddr("tcp", port)
    if err != nil {
        // handle error
    }

    ln, err := net.ListenTCP("tcp", tcp_address)
    if err != nil {
        // handle error
    }
    for {
        conn, err := ln.Accept()
        if err != nil {
            // handle error
        }
        go handleConnection(conn)
        // conn.Close()
    }
}
















