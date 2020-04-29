package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

type AuthHandle func(username, password string) bool
type TCPProtocol struct {
	cmd        byte
	atyp       byte
	ip         net.IP //when viaUDP is false, this is remote IP otherwise UDP client IP
	port       int    //when viaUDP is false, this is remote port otherwise UDP client port
	domain     string
	viaUDP     bool
	authHandle AuthHandle
}

func (p *TCPProtocol) handshake(conn *net.TCPConn) error {
	//version
	data, err := p.checkVersion(conn)
	p.writeBuf(conn, data)
	if err != nil {
		return err
	}
	//auth
	data, err = p.checkAuth(conn)
	p.writeBuf(conn, data)
	if err != nil {
		return err
	}
	//addr
	atyp, cmd, addrBytes, port, data, err := p.getAddr(conn)
	if err != nil {
		p.writeBuf(conn, data)
		return err
	} else {
		p.cmd = cmd
		p.atyp = atyp
	}
	switch p.atyp {
	case ATYPIPv4:
		p.ip = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
	case ATYPIPv6:
		p.ip = net.ParseIP(string(addrBytes))
	case ATYPDomain:
		p.domain = string(addrBytes)
		if addr, er := net.ResolveIPAddr("ip", p.domain); er != nil {
			p.writeBuf(conn, []byte{Version, 0x04, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return err
		} else {
			p.ip = addr.IP
		}
	}
	p.port = port

	//check remote addr
	switch p.cmd {
	case CmdConnect:
		if !p.ip.IsGlobalUnicast() || p.port <= 0 {
			p.writeBuf(conn, []byte{Version, 0x02, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return errors.New("remote address error")
		}
	case CmdUdpAssociate:
		p.viaUDP = true
	}
	return nil
}

func (p *TCPProtocol) checkVersion(conn *net.TCPConn) ([]byte, error) {
	var version byte
	var methodLen int

	if buf, err := p.readBuf(conn, 2); err != nil {
		return []byte{Version, MethodNone}, err
	} else {
		version = buf[0]
		methodLen = int(buf[1])
	}

	if version != Version || methodLen <= 0 {
		return []byte{Version, MethodNone}, errors.New("unsupported socks version")
	}

	if _, err := p.readBuf(conn, methodLen); err != nil {
		return []byte{Version, MethodNone}, err
	}

	if p.authHandle != nil {
		return []byte{Version, MethodAuth}, nil
	} else {
		return []byte{Version, MethodNoAuth}, nil
	}
}
func (p *TCPProtocol) checkAuth(conn *net.TCPConn) ([]byte, error) {
	if p.authHandle == nil {
		return nil, nil
	}

	var ver byte
	var userLen, passLen int
	var username, password string
	if buf, err := p.readBuf(conn, 2); err != nil {
		return []byte{0x01, 0x01}, err
	} else {
		ver = buf[0]
		userLen = int(buf[1])
	}

	if ver != 0x01 || userLen <= 0 {
		return []byte{0x01, 0x01}, errors.New("unsupported auth version or username is empty")
	}

	if buf, err := p.readBuf(conn, userLen); err != nil {
		return []byte{0x01, 0x01}, err
	} else {
		username = string(buf)
	}

	if buf, err := p.readBuf(conn, 1); err != nil {
		return []byte{0x01, 0x01}, err
	} else {
		passLen = int(buf[0])
	}

	if passLen <= 0 {
		return []byte{0x01, 0x01}, errors.New("password is empty")
	}

	if buf, err := p.readBuf(conn, passLen); err != nil {
		return []byte{0x01, 0x01}, err
	} else {
		password = string(buf)
	}

	if !p.authHandle(username, password) {
		return []byte{0x01, 0x01}, errors.New("username or password invalid")
	} else {
		return []byte{0x01, 0x00}, nil
	}
}
func (p *TCPProtocol) getAddr(conn *net.TCPConn) (atyp, cmd byte, addrBytes []byte, port int, data []byte, err error) {
	var ver byte
	if buf, er := p.readBuf(conn, 4); er != nil {
		err = er
		data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	} else {
		ver = buf[0]
		cmd = buf[1]
		atyp = buf[3]
	}

	if ver != Version {
		err = errors.New("unsupported socks version")
		data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}
	if bytes.IndexByte([]byte{CmdConnect, CmdUdpAssociate}, cmd) == -1 {
		err = errors.New("unsupported CMD")
		data = []byte{Version, 0x07, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}

	switch atyp {
	case ATYPIPv4:
		addrBytes, err = p.readBuf(conn, 4)
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	case ATYPDomain:
		var domainLen int
		if buf, er := p.readBuf(conn, 1); er != nil {
			err = er
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		} else {
			domainLen = int(buf[0])
		}
		if domainLen <= 0 {
			err = errors.New("length of domain is zero")
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
		addrBytes, err = p.readBuf(conn, domainLen)
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	case ATYPIPv6:
		addrBytes, err = p.readBuf(conn, 16)
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	default:
		err = errors.New("unsupported ATYP")
		data = []byte{Version, 0x08, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}

	if buf, er := p.readBuf(conn, 2); er != nil {
		err = er
		data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	} else {
		port = int(binary.BigEndian.Uint16(buf))
	}

	return
}

func (p *TCPProtocol) networkString() string {
	return p.ip.String() + ":" + strconv.Itoa(p.port)
}

func (p *TCPProtocol) readBuf(conn *net.TCPConn, ln int) ([]byte, error) {
	buf := make([]byte, ln)
	curReadLen := 0
	for curReadLen < ln {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 10))
		l, err := conn.Read(buf[curReadLen:])
		if err != nil {
			return nil, err
		}
		curReadLen += l
	}
	return buf, nil
}
func (p *TCPProtocol) writeBuf(conn *net.TCPConn, data []byte) {
	if data != nil && len(data) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 10))
		_, _ = conn.Write(data)
	}
}
