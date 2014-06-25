package nfparsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type NFLOWv5Header struct {
	Version           uint16
	Count             uint16
	Uptime            uint32
	Unix_secs         uint32
	Unix_nsecs        uint32
	Flow_seq          uint32
	Engine_type       uint8
	Engine_id         uint8
	Sampling_interval uint16
}

type NFLOWv5Record struct {
	Srcaddr   uint32
	Dstaddr   uint32
	Nexthop   uint32
	Input     uint16
	Output    uint16
	DPkts     uint32
	DOctets   uint32
	First     uint32
	Last      uint32
	Srcport   uint16
	Dstport   uint16
	Pad1      uint8
	Tcp_flags uint8
	Prot      uint8
	Tos       uint8
	Src_as    uint16
	Dst_as    uint16
	Src_mask  uint8
	Dst_mask  uint8
	Pad2      uint16
}

func NFV5HeaderUnpack(hdr []byte) NFLOWv5Header {
	var header NFLOWv5Header
	err := binary.Read(bytes.NewReader(hdr[:24]), binary.BigEndian, &header)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return header
}

func NFV5RecordUnpack(hdr []byte, flow_count uint16) []NFLOWv5Record {
	flow_list := make([]NFLOWv5Record, 31)
	//nflowv5's packets cant contains more than 30 records
	if flow_count > 30 {
		return flow_list
	}
	for cntr := 0; cntr < int(flow_count); cntr++ {
		var record NFLOWv5Record
		err := binary.Read(bytes.NewReader(hdr[24*cntr:24*cntr+48]), binary.BigEndian, &record)
		if err != nil {
			fmt.Println("binary.Read failed:", err)
		}
		flow_list[cntr] = record
	}
	return flow_list
}

func NFV5ParsePacket(packet []byte) []NFLOWv5Record {
	header := NFV5HeaderUnpack(packet)
	flow_list := NFV5RecordUnpack(packet, header.Count)
	return flow_list
}

func Test() {
	fmt.Println("test")
}
