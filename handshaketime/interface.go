package handshaketime

import (
	"net"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
)

type IPNotFound struct {}

func (e IPNotFound) Error() string {
	return "IP not found"
}

func GetIpByInterface(ifaceName string) (net.IP, error) {
	if iface, err := net.InterfaceByName(ifaceName); err != nil {
		return nil, err
	} else {
		if addrs, err := iface.Addrs(); err != nil {
			return nil, err
		} else {
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.To4() != nil {
						return v.IP.To4(), nil
					}
				}
			}
			return nil, IPNotFound{}
		}
	}
}

func StartMonitoring(ifaceName string) {
	if handle, err := pcap.OpenLive(ifaceName, 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp"); err != nil {
		panic(err)
	} else {
		db := createMemoryDB()

		if machineIP, err := GetIpByInterface(ifaceName); err != nil {
			panic(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				handlePacket(packet, machineIP, db)
			}
		}
	}
}