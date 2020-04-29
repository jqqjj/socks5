package main

const (
	Version byte = 0x05

	MethodNoAuth byte = 0x00
	MethodAuth   byte = 0x02
	MethodNone   byte = 0xFF

	CmdConnect      byte = 0x01
	CmdUdpAssociate byte = 0x03

	ATYPIPv4   byte = 0x01
	ATYPDomain byte = 0x03
	ATYPIPv6   byte = 0x04
)
