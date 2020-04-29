package main

import (
	"errors"
	"net"
	"sync"
)

func NewServer() *server {
	return &server{
		readTimeoutSecond:  600,
		writeTimeoutSecond: 30,
	}
}

type server struct {
	listener           *net.TCPListener
	mutex              sync.Mutex
	enableUDP          bool
	readTimeoutSecond  uint //default 600
	writeTimeoutSecond uint //default 30
	headRequest        *requestList

	authHandle        AuthHandle
	onConnectedHandle OnConnectedHandle
	onStartedHandle   OnStartedHandle
}

func (s *server) SetAuthHandle(handle AuthHandle) {
	s.authHandle = handle
}
func (s *server) EnableUDP() {
	s.enableUDP = true
}
func (s *server) SetReadTimeOutSecond(second uint) {
	s.readTimeoutSecond = second
}
func (s *server) SetWriteTimeOutSecond(second uint) {
	s.writeTimeoutSecond = second
}
func (s *server) OnStarted(h OnStartedHandle) {
	s.onStartedHandle = h
}
func (s *server) OnConnected(h OnConnectedHandle) {
	s.onConnectedHandle = h
}
func (s *server) Close() error {
	if s.listener == nil {
		return errors.New("server is not running")
	}
	if err := s.listener.Close(); err != nil {
		return err
	} else {
		return nil
	}
}
func (s *server) Run(addr *net.TCPAddr) error {
	var err error
	s.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	if s.onStartedHandle != nil {
		s.onStartedHandle(s.listener)
	}
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			break
		}
		go connHandle(conn, s)
	}

	s.listener = nil
	s.closeRequests()
	return nil
}

func (s *server) closeRequests() {
	for s.headRequest != nil {
		r := s.headRequest
		s.removeRequestList(r)
		_ = r.data.Close()
	}
}
func connHandle(conn *net.TCPConn, s *server) {
	r := &requestList{
		prev: nil, next: nil,
		data: Request{ClientConn: conn, server: s},
	}
	s.insertRequestList(r)
	r.data.Process()
	s.removeRequestList(r)
	_ = r.data.Close()
}

func (s *server) insertRequestList(l *requestList) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.headRequest != nil {
		s.headRequest.prev = l
		l.next = s.headRequest
		s.headRequest = l
	} else {
		s.headRequest = l
	}
}
func (s *server) removeRequestList(l *requestList) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.headRequest == l {
		s.headRequest = l.next
	}
	if l.prev != nil {
		l.prev.next = l.next
		l.prev = nil
	}
	if l.next != nil {
		l.next.prev = l.prev
		l.next = nil
	}
}
