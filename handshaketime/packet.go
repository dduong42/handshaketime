package handshaketime

import (
	"net"
	"time"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
)

func getSrc(packet gopacket.Packet) net.IP {
	var ipv4 layers.IPv4

	ipv4_layer := packet.NetworkLayer()
	ipv4.DecodeFromBytes(ipv4_layer.LayerContents(), gopacket.NilDecodeFeedback)
	return ipv4.SrcIP
}

func getTcp(packet gopacket.Packet) layers.TCP {
	var tcp layers.TCP

	tcp_layer := packet.TransportLayer()
	tcp.DecodeFromBytes(tcp_layer.LayerContents(), gopacket.NilDecodeFeedback)
	return tcp
}

func isSyn(tcp layers.TCP) bool {
	return tcp.SYN && !tcp.ACK
}

func isAck(tcp layers.TCP) bool {
	return !tcp.SYN && tcp.ACK
}

func handlePacket(packet gopacket.Packet, machineIP net.IP, db DatabaseProxy) {
	if src := getSrc(packet); !src.Equal(machineIP) {
		tcp := getTcp(packet)
		if isSyn(tcp) {
			synPacket := SynPacket{ip: src, timeReceived: time.Now(), sequenceNumber: tcp.Seq}
			db.saveSynPacket(synPacket)
		} else if isAck(tcp) {
			if synPacket, err := db.getSynPacket(tcp.Seq - 1); err == nil {
				handshakeTime := HandshakeTime{ip: src, time: time.Now().Sub(synPacket.timeReceived)}
				db.deleteSynPacket(synPacket)
				db.saveHandshakeTime(handshakeTime)
				fmt.Println("IP: ", src, "Time: ", handshakeTime.time)
			}
		}
	}
}
