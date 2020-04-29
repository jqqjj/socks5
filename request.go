package main

import (
	"encoding/binary"
	"net"
	"time"
)

type Request struct {
	tcpGram TCPProtocol
	udpGram UDPProtocol

	ClientConn *net.TCPConn
	RemoteConn *net.TCPConn

	UDPConn *net.UDPConn

	server *server
}

type requestList struct {
	prev *requestList
	data Request
	next *requestList
}

func (r *Request) Close() error {
	var err error
	if r.ClientConn != nil {
		er := r.ClientConn.Close()
		if er != nil {
			err = er
		}
	}
	if r.RemoteConn != nil {
		er := r.RemoteConn.Close()
		if er != nil {
			err = er
		}
	}
	if r.UDPConn != nil {
		er := r.UDPConn.Close()
		if er != nil {
			err = er
		}
	}
	return err
}
func (r *Request) Process() {
	if err := r.tcpGram.handshake(r.ClientConn); err != nil {
		return
	}

	if !r.tcpGram.viaUDP { //tcp
		//answer bind addr
		if conn, err := net.DialTimeout("tcp", r.tcpGram.networkString(), time.Second*time.Duration(r.server.writeTimeoutSecond)); err != nil {
			_, _ = r.ClientConn.Write([]byte{Version, 0x04, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		} else {
			r.RemoteConn = conn.(*net.TCPConn)
		}

		bindIP := r.ClientConn.LocalAddr().(*net.TCPAddr).IP
		res := make([]byte, 0, 22)
		if ip := bindIP.To4(); ip != nil {
			//IPv4, len is 4
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv4}...)
			res = append(res, ip...)
		} else {
			//IPv6, len is 16
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv6}...)
			res = append(res, bindIP...)
		}

		portByte := [2]byte{}
		binary.BigEndian.PutUint16(portByte[:], uint16(r.ClientConn.LocalAddr().(*net.TCPAddr).Port))
		res = append(res, portByte[:]...)
		if _, err := r.ClientConn.Write(res); err != nil {
			return
		}

		r.transformTCP()
	} else {
		//bind UDP addr and answer
		if !r.server.enableUDP {
			_, _ = r.ClientConn.Write([]byte{Version, 0x07, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
		//Listen on UDP
		if udpAddr, err := net.ResolveUDPAddr("udp", ":0"); err != nil {
			_, _ = r.ClientConn.Write([]byte{Version, 0x01, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		} else {
			if udpConn, err := net.ListenUDP("udp", udpAddr); err != nil {
				_, _ = r.ClientConn.Write([]byte{Version, 0x01, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				return
			} else {
				r.UDPConn = udpConn
			}
		}

		bindIP := r.ClientConn.LocalAddr().(*net.TCPAddr).IP
		res := make([]byte, 0, 22)
		if ip := bindIP.To4(); ip != nil {
			//IPv4, len is 4
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv4}...)
			res = append(res, ip...)
		} else {
			//IPv6, len is 16
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv6}...)
			res = append(res, bindIP...)
		}

		portByte := [2]byte{}
		binary.BigEndian.PutUint16(portByte[:], uint16(r.UDPConn.LocalAddr().(*net.UDPAddr).Port))
		res = append(res, portByte[:]...)
		if _, err := r.ClientConn.Write(res); err != nil {
			return
		}

		if r.tcpGram.ip.IsGlobalUnicast() && r.tcpGram.port > 0 {
			r.udpGram.clientAddr = &net.UDPAddr{IP: r.tcpGram.ip, Port: r.tcpGram.port}
		}

		r.transformUDP()
	}
}

func (r *Request) transformTCP() {
	if r.server.onConnectedHandle != nil {
		var target string
		switch r.tcpGram.atyp {
		case ATYPIPv4:
			target = r.tcpGram.ip.String()
		case ATYPIPv6:
			target = r.tcpGram.ip.String()
		case ATYPDomain:
			target = r.tcpGram.domain
		}
		r.server.onConnectedHandle("tcp", target, r.tcpGram.port)
	}
	done := make(chan int)

	go func() {
		defer func() { _ = r.Close(); done <- 0 }()
		buf := make([]byte, 1024*8)
		for {
			_ = r.RemoteConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.server.readTimeoutSecond)))
			if ln, err := r.RemoteConn.Read(buf); err != nil {
				break
			} else {
				_ = r.ClientConn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.server.writeTimeoutSecond)))
				if _, err := r.ClientConn.Write(buf[:ln]); err != nil {
					break
				}
			}
		}
	}()

	buf := make([]byte, 1024*8)
	for {
		_ = r.ClientConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.server.readTimeoutSecond)))
		if ln, err := r.ClientConn.Read(buf); err != nil {
			break
		} else {
			_ = r.RemoteConn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.server.writeTimeoutSecond)))
			if _, err := r.RemoteConn.Write(buf[:ln]); err != nil {
				break
			}
		}
	}
	_ = r.Close()

	<-done
}

func (r *Request) transformUDP() {
	doneTCP := make(chan int)
	doneExchange := make(chan int)

	go func() {
		defer func() { _ = r.Close(); doneTCP <- 0 }()
		buf := make([]byte, 1)
		for {
			if _, err := r.ClientConn.Read(buf); err != nil {
				break
			}
		}
	}()

	//init UDPExchange
	if r.udpGram.UDPExchangeMap == nil {
		r.udpGram.UDPExchangeMap = make(map[string]*UDPExchange)
	}

	go func() {
		for {
			select {
			case <-time.After(time.Second * 2):
				r.udpGram.udpMutex.Lock()
				for k, v := range r.udpGram.UDPExchangeMap {
					if v.IsExpired() {
						delete(r.udpGram.UDPExchangeMap, k)
					}
				}
				r.udpGram.udpMutex.Unlock()
			case <-doneExchange:
				return
			}
		}

	}()

	buf := make([]byte, 65535)
	for {
		_ = r.UDPConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(r.server.readTimeoutSecond)))
		ln, fromAddr, err := r.UDPConn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		//get client addr and remote addr via the first package
		if r.udpGram.clientAddr == nil {
			r.udpGram.clientAddr = fromAddr
		}

		if r.udpGram.clientAddr.IP.Equal(fromAddr.IP) && r.udpGram.clientAddr.Port == fromAddr.Port { //package from client
			header, body, err := r.udpGram.handshake(buf[:ln])
			if err != nil {
				break
			}
			r.udpGram.udpMutex.Lock()
			if exchange, ok := r.udpGram.UDPExchangeMap[r.udpGram.remoteAddr().String()]; !ok {
				r.udpGram.UDPExchangeMap[r.udpGram.remoteAddr().String()] = NewUDPExchange(header, 60)

				if r.server.onConnectedHandle != nil {
					var target string
					switch r.udpGram.atyp {
					case ATYPIPv4:
						target = r.udpGram.ip.String()
					case ATYPIPv6:
						target = r.udpGram.ip.String()
					case ATYPDomain:
						target = r.udpGram.domain
					}
					r.server.onConnectedHandle("udp", target, r.udpGram.port)
				}

			} else {
				exchange.Delay(60)
			}
			r.udpGram.udpMutex.Unlock()

			_ = r.UDPConn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.server.writeTimeoutSecond)))
			if _, er := r.UDPConn.WriteToUDP(body, r.udpGram.remoteAddr()); er != nil {
				break
			}
		} else {
			r.udpGram.udpMutex.Lock()
			if exchange, ok := r.udpGram.UDPExchangeMap[fromAddr.String()]; ok { //package from remote
				body := append(exchange.headerData, buf[:ln]...)
				exchange.Delay(60)
				_ = r.UDPConn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(r.server.writeTimeoutSecond)))
				if _, er := r.UDPConn.WriteToUDP(body, r.udpGram.clientAddr); er != nil {
					break
				}
			}
			r.udpGram.udpMutex.Unlock()
		}
	}
	close(doneExchange)
	_ = r.Close()

	<-doneTCP
}
