package nfparsers

import (
    "fmt"
    "encoding/binary"
    "bytes"
)

type IPFIXMsgHeader struct {
    Version uint16
    Length uint16
    ExportTime uint32
    SequenceNumber uint32
    DomainID uint32
}

type IPFIXSetHeader struct {
    SetID uint16
    Length uint16
}

type IPFIXTmpltHeader struct {
    TmpltID uint16
    FieldCount uint16
}


type IPFIXIETFElem struct {
    IEID uint16
    FieldLength uint16
}

/*
    this is an emulated structure, which compatible with NFLOWv5's one.
    (have same fields name etc). IPV6 only
*/
type IPFIXGenericV4Record struct{
    Srcaddr uint32
    Dstaddr uint32
    Nexthop uint32
    Input   uint16
    Output  uint16
    DPkts   uint32
    DOctets uint32
    First   uint32
    Last    uint32
    Srcport uint16
    Dstport uint16
    Tcp_flags   uint8
    Prot    uint8
    Tos     uint8
    Src_as  uint16
    Dst_as  uint16
    Src_mask    uint8
    Dst_mask    uint8
    Pad2    uint16
}


func IPFIXMsgHeaderUnpack(hdr []byte) IPFIXMsgHeader {
    var header IPFIXMsgHeader
    err := binary.Read(bytes.NewReader(hdr[:16]), binary.BigEndian, &header)
    if err != nil {
       fmt.Println("binary.Read failed:", err)
    }
    return header
}

func IPFIXSetHeaderUnpack(hdr []byte) IPFIXSetHeader {
    var header IPFIXSetHeader
    err := binary.Read(bytes.NewReader(hdr[16:20]), binary.BigEndian, &header)
    if err != nil {
        fmt.Println("binary.Read failed:", err)
    }
    return header
}

func IPFIXTmpltHeaderUnpack(hdr []byte) IPFIXTmpltHeader {
    var header IPFIXTmpltHeader
    err := binary.Read(bytes.NewReader(hdr[20:24]), binary.BigEndian, &header)
    if err != nil {
        fmt.Println("binary.Read failed:", err)
    }
    return header
}

func IPFIXParseTmpltSet(packet []byte, agent_ip uint32,
                        ipfix_tmplt_len map[uint32]map[uint16]map[uint16]uint16,
                        ipfix_tmplt_fields map[uint32]map[uint16]map[uint16]uint8){
    tmplt_header := IPFIXTmpltHeaderUnpack(packet)
    _,exist := ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID][0]
    if exist {
    fmt.Println(ipfix_tmplt_len)
        return
    }

    _,len_dict_exist := ipfix_tmplt_len[agent_ip]
    if !len_dict_exist {
        ipfix_tmplt_len[agent_ip] = make(map[uint16]map[uint16]uint16)
        ipfix_tmplt_fields[agent_ip] = make(map[uint16]map[uint16]uint8)
    }
    ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID] = make(map[uint16]uint16)
    ipfix_tmplt_fields[agent_ip][tmplt_header.TmpltID] = make(map[uint16]uint8)

    offset := 24
    for cntr := uint16(0); cntr < tmplt_header.FieldCount; cntr++{
        var fspec IPFIXIETFElem
        err := binary.Read(bytes.NewReader(packet[offset:offset+4]), binary.BigEndian, &fspec)
        if err != nil {
            fmt.Println("IETF Parsing. binary.Read failed:", err)
        }
        if (fspec.IEID >> 15) == 0 {
            ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID][cntr] = fspec.FieldLength
            ipfix_tmplt_fields[agent_ip][tmplt_header.TmpltID][cntr] = uint8(fspec.IEID)
            offset += 4

        } else {
            offset += 8
        }
    }
    fmt.Println(ipfix_tmplt_len)
}

func IPFIXParseDataSet(packet []byte, set_hdr *IPFIXSetHeader,
                       tmplt_fields_len map[uint16]uint16,
                       tmplt_fields_type map[uint16]uint8){
    cntr := uint16(0)
    for offset := uint16(20); offset < (*set_hdr).Length; {
        offset_ends := offset + tmplt_fields_len[cntr] + 1
        cntr++
        offset = offset_ends
    }
}

func IPFIXParsePacket(packet []byte, agent_ip uint32,
                      ipfix_tmplt_len map[uint32]map[uint16]map[uint16]uint16,
                      ipfix_tmplt_fields map[uint32]map[uint16]map[uint16]uint8){
    set_hdr := IPFIXSetHeaderUnpack(packet)
    if set_hdr.SetID == 2 {
        IPFIXParseTmpltSet(packet, agent_ip, ipfix_tmplt_len, ipfix_tmplt_fields)
    } else {
        _,exist := ipfix_tmplt_len[agent_ip][set_hdr.SetID][0]
        if exist {
            IPFIXParseDataSet(packet, &set_hdr, ipfix_tmplt_len[agent_ip][set_hdr.SetID],
                              ipfix_tmplt_fields[agent_ip][set_hdr.SetID])
        } else {
        }
    }
}
