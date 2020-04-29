package main

import (
	"errors"
	"time"
)

type UDPExchange struct {
	expiredTime time.Time
	headerData  []byte
}

func NewUDPExchange(headerData []byte, lifetime uint) *UDPExchange {
	h := make([]byte, len(headerData))
	copy(h, headerData)
	return &UDPExchange{
		headerData:  h,
		expiredTime: time.Now().Add(time.Second * time.Duration(lifetime)),
	}
}

func (e *UDPExchange) GetHeaderData() ([]byte, error) {
	if e.IsExpired() {
		return nil, errors.New("UDPExchange is expired")
	}
	return e.headerData, nil
}
func (e *UDPExchange) IsExpired() bool {
	return e.expiredTime.Unix() < time.Now().Unix()
}
func (e *UDPExchange) Delay(second uint) {
	e.expiredTime = time.Now().Add(time.Second * time.Duration(second))
}
