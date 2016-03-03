package main

import (
    "fmt"
    "os"
    "net"
    "net/http"
    "bufio"
)

const EXIT_FAILURE = 1

func usage() {
    fmt.Println("Usage: proxy <port-number>")
    os.Exit(EXIT_FAILURE)
}

func handleConnection(connection net.Conn) {
    defer connection.Close()

    request, error := http.ReadRequest(bufio.NewReader(connection))
    url := request.URL

    request_line := []byte("GET " + url + " HTTP/1.0\r\n")

}

func main() {
    if len(os.Args) != 2 {
        usage()
    }
    port = ":" + os.Args[1]

    tcp_address, err := net.ResolveTCPAddr("tcp", port)

    ln, err := net.Listen("tcp", port)
    if err != nil {
        // handle error
    }
    for {
        conn, err := ln.Accept()
        if err != nil {
            // handle error
        }
        go handleConnection(conn)
    }
}















