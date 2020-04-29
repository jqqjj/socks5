package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

type UDPProtocol struct {
	rsv  [2]byte
	flag byte
	atyp byte
	ip   net.IP
	port int

	domain string

	clientAddr *net.UDPAddr

	UDPExchangeMap map[string]*UDPExchange
	udpMutex       sync.Mutex
}

func (p *UDPProtocol) handshake(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 || !bytes.Equal(buf[:2], p.rsv[:]) || buf[2] != p.flag {
		return nil, nil, errors.New("fail")
	}

	var header, body []byte
	p.atyp = buf[3]

	switch p.atyp {
	case ATYPIPv4:
		if len(buf) < 10 {
			return nil, nil, errors.New("header is too short for IPv4")
		}
		p.ip = net.IPv4(buf[4], buf[5], buf[6], buf[7])
		p.port = int(binary.BigEndian.Uint16(buf[8:10]))
		body = buf[10:]
		header = buf[:10]
	case ATYPDomain:
		if len(buf) < 5 {
			return nil, nil, errors.New("header is too short for domain")
		}
		domainLen := int(buf[4])
		if domainLen <= 0 || len(buf) < 5+domainLen+2 {
			return nil, nil, errors.New("header is too short for domain")
		}
		p.domain = string(buf[5 : 5+domainLen])
		if ipAddr, err := net.ResolveIPAddr("ip", p.domain); err != nil {
			return nil, nil, errors.New("can't resolve domain:" + p.domain)
		} else {
			p.ip = ipAddr.IP
			p.port = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
		}
		body = buf[5+domainLen+2:]
		header = buf[:5+domainLen+2]
	case ATYPIPv6:
		if len(buf) < 22 {
			return nil, nil, errors.New("header is too short for IPv6")
		}
		p.ip = net.ParseIP(string(buf[4:20]))
		p.port = int(binary.BigEndian.Uint16(buf[20:22]))
		body = buf[22:]
		header = buf[:22]
	default:
		return nil, nil, errors.New("unsupported atyp")
	}

	h := make([]byte, len(header))
	copy(h, header)
	return h, body, nil
}

func (p *UDPProtocol) remoteAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: p.ip, Port: p.port}
}
