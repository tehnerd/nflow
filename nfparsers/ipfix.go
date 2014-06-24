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
        return
    }

    ipfix_tmplt_len[agent_ip] = make(map[uint16]map[uint16]uint16)
    ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID] = make(map[uint16]uint16)
    ipfix_tmplt_fields[agent_ip] = make(map[uint16]map[uint16]uint8)
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
    fmt.Println(ipfix_tmplt_fields)

}

func IPFIXParsePacket(packet []byte, agent_ip uint32,
                      ipfix_tmplt_len map[uint32]map[uint16]map[uint16]uint16,
                      ipfix_tmplt_fields map[uint32]map[uint16]map[uint16]uint8){
    set_hdr := IPFIXSetHeaderUnpack(packet)
    if set_hdr.SetID == 2 {
        IPFIXParseTmpltSet(packet, agent_ip, ipfix_tmplt_len, ipfix_tmplt_fields)
    }
}
