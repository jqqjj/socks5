package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
)

var (
	port int

	username string
	password string
)

func init() {
	flag.StringVar(&username, "user", "", "username")
	flag.StringVar(&password, "pwd", "", "password")
	flag.IntVar(&port, "p", 1080, "port on listen, must be greater than 0")
	flag.Parse()
}

func main() {
	if port <= 0 {
		flag.Usage()
		os.Exit(1)
	}
	var serverAddr *net.TCPAddr
	if addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(port)); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		serverAddr = addr
	}

	server := NewServer()
	server.EnableUDP()
	server.OnStarted(func(listener *net.TCPListener) {
		fmt.Println("start server on", listener.Addr().String())
	})
	server.OnConnected(func(network, address string, port int) {
		fmt.Println("["+network+"]connect to:", address+":"+strconv.Itoa(port))
	})
	if username != "" || password != "" {
		server.SetAuthHandle(handlerAuth)
	}
	if err := server.Run(serverAddr); err != nil {
		fmt.Println("Run socks5 server error:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Socks5 server normal exit.")
	os.Exit(0)
}

func handlerAuth(u, p string) bool {
	return u == username && p == password
}
