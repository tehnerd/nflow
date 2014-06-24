package main

import (
    "fmt"
    "net"
    "os"
    "time"
    "bufio"
    "nflow/nfparsers"
    "strings"
    "strconv"
    "sync"
)



func inet_ntoa(ipnr int64) net.IP {   
    var bytes [4]byte
    bytes[0] = byte(ipnr & 0xFF)
    bytes[1] = byte((ipnr >> 8) & 0xFF)
    bytes[2] = byte((ipnr >> 16) & 0xFF)
    bytes[3] = byte((ipnr >> 24) & 0xFF)
    return net.IPv4(bytes[3],bytes[2],bytes[1],bytes[0])
}

func addr2uint32(addr *net.UDPAddr) uint32 {
        a := (*addr).IP.To4()
        var u uint32
        u |= uint32(a[0])
        u |= uint32(a[1]) << 8
        u |= uint32(a[2]) << 16
        u |= uint32(a[3]) << 24
        return u
}

func string_to_uint32(ip string) uint32 {
    bits := strings.Split(ip, ".")
    b0, _ := strconv.Atoi(bits[0])
    b1, _ := strconv.Atoi(bits[1])
    b2, _ := strconv.Atoi(bits[2])
    b3, _ := strconv.Atoi(bits[3])
    var ip_uint32 uint32
    ip_uint32 += uint32(b0) << 24
    ip_uint32 += uint32(b1) << 16
    ip_uint32 += uint32(b2) << 8
    ip_uint32 += uint32(b3)
    return ip_uint32
}



func collect_flow(sock *net.UDPConn, mutex *sync.RWMutex,
                  vips_pps map[uint32]uint32,
                  vips_flags map[uint32]uint8,
                  vips_baseline map[uint32]uint32,
                  vips_multiplier map[uint32]uint8){
    buffer := make([]byte, 9000)
    ipfix_tmplt_len := make(map[uint32]map[uint16]map[uint16]uint16)
    ipfix_tmplt_fields := make(map[uint32]map[uint16]map[uint16]uint8)
    for {
        n,addr,_ := sock.ReadFromUDP(buffer)
        switch buffer[1] {
            case 5:{
                flow_list := nfparsers.NFV5ParsePacket(buffer[:n])
                for cntr := 0; cntr < len(flow_list); cntr++{
                    mutex.RLock()
                    _,exist := vips_pps[flow_list[cntr].Dstaddr]
                    mutex.RUnlock()
                    if exist {
                        mutex.Lock()
                        vips_pps[flow_list[cntr].Dstaddr] += flow_list[cntr].DPkts
                        mutex.Unlock()
                    }
                }
            }
            case 10:{
                nfparsers.IPFIXParsePacket(buffer[:n],addr2uint32(addr),
                                 ipfix_tmplt_len, ipfix_tmplt_fields)
            }
        }
    }
}

func analyze_stats(mutex *sync.RWMutex,
                   vips_pps map[uint32]uint32,
                   vips_flags map[uint32]uint8,
                   vips_baseline map[uint32]uint32,
                   vips_multiplier map[uint32]uint8){
    mutex.Lock()
    for k,v := range vips_pps {
        if(v != uint32(0)) {
            if(vips_baseline[k] != uint32(0)) {
                if (v > 10 && v > vips_baseline[k]*uint32(vips_multiplier[k])){
                    fmt.Println("possible ddos on")
                    vips_flags[k] = uint8(1)
                } else {
                    vips_flags[k] = uint8(0)
                    }
            }
            vips_baseline[k] = v
            vips_pps[k] = uint32(0)
        }
    }
    mutex.Unlock()
}

func main(){
    if len(os.Args) < 2{
        os.Exit(1)
    }
    fd,err := os.Open(os.Args[1])
    if err != nil {
        os.Exit(1)
    }
    cfg_reader := bufio.NewReader(fd)
    vips_pps := make(map[uint32]uint32)
    vips_flags := make(map[uint32]uint8)
    vips_baseline := make(map[uint32]uint32)
    vips_multiplier := make(map[uint32]uint8)
    line,err := cfg_reader.ReadString('\n')
    for err == nil {
        fields := strings.Fields(line)
        vip_ip := string_to_uint32(string(fields[0]))
        vip_mult,_ := strconv.ParseInt(string(fields[1]), 10, 8)
        vips_pps[uint32(vip_ip)] = 0
        vips_flags[uint32(vip_ip)] = 0
        vips_baseline[uint32(vip_ip)] = 0
        vips_multiplier[uint32(vip_ip)] = uint8(vip_mult)
        line,err = cfg_reader.ReadString('\n')
    }
    var mutex sync.RWMutex
    const nfport = ":5001"
    fmt.Println("go lang go")
    sock_addr, _ := net.ResolveUDPAddr("udp", nfport)
    dsock, err := net.ListenUDP("udp",sock_addr)
    if err != nil {
        fmt.Println("cant open udp socket")
        os.Exit(1)
    }
    go collect_flow(dsock, &mutex, vips_pps, vips_flags, vips_baseline, vips_multiplier)
    for {
        time.Sleep(1*time.Minute)
        analyze_stats(&mutex, vips_pps, vips_flags, vips_baseline, vips_multiplier)
    }
}
