package main

import (
    "fmt"
    "net"
    "os"
    "nflow/nfparsers"
)



func main(){
    const nfport = ":5000"
    fmt.Println("go lang go")
    buffer := make([]byte, 9000)
    sock_addr, _ := net.ResolveUDPAddr("udp", nfport)
    dsock, err := net.ListenUDP("udp",sock_addr)
    nfparsers.Test()
    if err != nil {
        fmt.Println("cant open udp socket")
        os.Exit(-1)
    }
    for {
        n,_,_ := dsock.ReadFromUDP(buffer)
        switch buffer[1] {
            case 5:
                nfparsers.NFV5ParsePacket(buffer[:n])
        }
    }
}
