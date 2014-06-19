package main

import (
    "fmt"
    "net"
    "os"
    "time"
    "nflow/nfparsers"
)

func collect_flow(sock *net.UDPConn){
    buffer := make([]byte, 9000)
    for {
        n,_,_ := sock.ReadFromUDP(buffer)
        switch buffer[1] {
            case 5:
                nfparsers.NFV5ParsePacket(buffer[:n])
        }
    }
}

func main(){
    const nfport = ":5001"
    fmt.Println("go lang go")
    sock_addr, _ := net.ResolveUDPAddr("udp", nfport)
    dsock, err := net.ListenUDP("udp",sock_addr)
    if err != nil {
        fmt.Println("cant open udp socket")
        os.Exit(-1)
    }
    go collect_flow(dsock)
    for {
        time.Sleep(1*time.Minute)
    }
}
