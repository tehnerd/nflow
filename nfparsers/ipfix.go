package nfparsers

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type IPFIXMsgHeader struct {
	Version        uint16
	Length         uint16
	ExportTime     uint32
	SequenceNumber uint32
	DomainID       uint32
}

type IPFIXSetHeader struct {
	SetID  uint16
	Length uint16
}

type IPFIXTmpltHeader struct {
	TmpltID    uint16
	FieldCount uint16
}

type IPFIXIETFElem struct {
	IEID        uint16
	FieldLength uint16
}

/*
   this is an emulated structure, which compatible with NFLOWv5's one.
   (have same fields name etc). IPV4 only
*/
type IPFIXGenericV4Record struct {
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
	Tcp_flags uint8
	Prot      uint8
	Tos       uint8
	Src_as    uint16
	Dst_as    uint16
	Src_mask  uint8
	Dst_mask  uint8
}

func (record *IPFIXGenericV4Record) SetSrcaddr(srcaddr uint32)   { record.Srcaddr = srcaddr }
func (record *IPFIXGenericV4Record) SetDstaddr(dstaddr uint32)   { record.Dstaddr = dstaddr }
func (record *IPFIXGenericV4Record) SetNexthop(nexthop uint32)   { record.Nexthop = nexthop }
func (record *IPFIXGenericV4Record) SetInput(input uint16)       { record.Input = input }
func (record *IPFIXGenericV4Record) SetOutput(output uint16)     { record.Output = output }
func (record *IPFIXGenericV4Record) SetDPkts(dpkts uint32)       { record.DPkts = dpkts }
func (record *IPFIXGenericV4Record) SetDOctets(doctets uint32)   { record.DOctets = doctets }
func (record *IPFIXGenericV4Record) SetFirst(first uint32)       { record.First = first }
func (record *IPFIXGenericV4Record) SetLast(last uint32)         { record.Last = last }
func (record *IPFIXGenericV4Record) SetSrcport(srcport uint16)   { record.Srcport = srcport }
func (record *IPFIXGenericV4Record) SetDstport(dstport uint16)   { record.Dstport = dstport }
func (record *IPFIXGenericV4Record) SetTcp_flags(tcpflags uint8) { record.Tcp_flags = tcpflags }
func (record *IPFIXGenericV4Record) SetProt(prot uint8)          { record.Prot = prot }
func (record *IPFIXGenericV4Record) SetTos(tos uint8)            { record.Tos = tos }
func (record *IPFIXGenericV4Record) SetSrc_as(src_as uint16)     { record.Src_as = src_as }
func (record *IPFIXGenericV4Record) SetDst_as(dst_as uint16)     { record.Dst_as = dst_as }
func (record *IPFIXGenericV4Record) SetSrc_mask(src_mask uint8)  { record.Src_mask = src_mask }
func (record *IPFIXGenericV4Record) SetDst_mask(dst_mask uint8)  { record.Dst_mask = dst_mask }

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
	ipfix_tmplt_fields map[uint32]map[uint16]map[uint16]uint8) {
	tmplt_header := IPFIXTmpltHeaderUnpack(packet)
	_, exist := ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID][0]
	if exist {
		return
	}

	_, len_dict_exist := ipfix_tmplt_len[agent_ip]
	if !len_dict_exist {
		ipfix_tmplt_len[agent_ip] = make(map[uint16]map[uint16]uint16)
		ipfix_tmplt_fields[agent_ip] = make(map[uint16]map[uint16]uint8)
	}
	ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID] = make(map[uint16]uint16)
	ipfix_tmplt_fields[agent_ip][tmplt_header.TmpltID] = make(map[uint16]uint8)

	offset := 24
	for cntr := uint16(0); cntr < tmplt_header.FieldCount; cntr++ {
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
			ipfix_tmplt_len[agent_ip][tmplt_header.TmpltID][cntr] = fspec.FieldLength
			offset += 8
		}
	}
}

// ugly. will think how to remake it; right now we are trying just to make things work
func GenerateIPFIXGenericV4Record(record *IPFIXGenericV4Record, data_slice []byte,
	field_type uint8, bo binary.ByteOrder) {
	switch field_type {
	case 8:
		record.SetSrcaddr(bo.Uint32(data_slice))
	case 12:
		record.SetDstaddr(bo.Uint32(data_slice))
	case 15:
		record.SetNexthop(bo.Uint32(data_slice))
	case 10:
		record.SetInput(uint16(bo.Uint32(data_slice)))
	case 14:
		record.SetOutput(uint16(bo.Uint32(data_slice)))
	case 2:
		record.SetDPkts(uint32(bo.Uint64(data_slice)))
	case 1:
		record.SetDOctets(uint32(bo.Uint64(data_slice)))
	case 21:
		record.SetFirst(bo.Uint32(data_slice))
	case 22:
		record.SetLast(bo.Uint32(data_slice))
	case 7:
		record.SetSrcport(bo.Uint16(data_slice))
	case 11:
		record.SetDstport(bo.Uint16(data_slice))
	case 6:
		record.SetTcp_flags(uint8(data_slice[0]))
	case 4:
		record.SetProt(uint8(data_slice[0]))
	case 5:
		record.SetTos(uint8(data_slice[0]))
	case 16:
		record.SetSrc_as(uint16(bo.Uint32(data_slice)))
	case 17:
		record.SetDst_as(uint16(bo.Uint32(data_slice)))
	case 9:
		record.SetSrc_mask(uint8(data_slice[0]))
	case 13:
		record.SetDst_mask(uint8(data_slice[0]))
	}
}

func IPFIXParseDataSet(packet []byte, set_hdr *IPFIXSetHeader,
	tmplt_fields_len map[uint16]uint16,
	tmplt_fields_type map[uint16]uint8) []IPFIXGenericV4Record {
	//not sure how many records could be in ipfix set. gonna start from 41
	flow_list := make([]IPFIXGenericV4Record, 41)
	bo := binary.BigEndian
	for offset := uint16(20); offset < (*set_hdr).Length; {
		cntr := uint16(0)
		var record IPFIXGenericV4Record
		for ; cntr < uint16(len(tmplt_fields_len)); cntr++ {
			offset_ends := offset + tmplt_fields_len[cntr]
			GenerateIPFIXGenericV4Record(&record, packet[offset:offset_ends],
				tmplt_fields_type[cntr], bo)
			offset = offset_ends
		}
		flow_list = append(flow_list, record)
	}
	return flow_list
}

func IPFIXParsePacket(packet []byte, agent_ip uint32,
	ipfix_tmplt_len map[uint32]map[uint16]map[uint16]uint16,
	ipfix_tmplt_fields map[uint32]map[uint16]map[uint16]uint8) []IPFIXGenericV4Record {
	set_hdr := IPFIXSetHeaderUnpack(packet)
	if set_hdr.SetID == 2 {
		IPFIXParseTmpltSet(packet, agent_ip, ipfix_tmplt_len, ipfix_tmplt_fields)
	} else {
		_, exist := ipfix_tmplt_len[agent_ip][set_hdr.SetID][0]
		if exist {
			flow_list := IPFIXParseDataSet(packet, &set_hdr, ipfix_tmplt_len[agent_ip][set_hdr.SetID],
				ipfix_tmplt_fields[agent_ip][set_hdr.SetID])
			return flow_list
		}
	}
	return make([]IPFIXGenericV4Record, 0, 0)
}
