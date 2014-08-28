package handshaketime

import (
	"net"
	"time"
)


type SynPacket struct {
	ip net.IP
	timeReceived time.Time
	sequenceNumber uint32
}

type HandshakeTime struct {
	ip net.IP
	time time.Duration
}

type DatabaseProxy interface {
	saveSynPacket(SynPacket)
	getSynPacket(uint32) (SynPacket, error)
	deleteSynPacket(SynPacket)
	saveHandshakeTime(HandshakeTime)
	getHandshakeTimes() []HandshakeTime
}

type SynPacketLite struct {
	ip net.IP
	timeReceived time.Time
}

type MemoryDB struct {
	synPacketMap map[uint32]SynPacketLite
	handshakeTimeSlice []HandshakeTime
}

type SynPacketNotFound struct {}


func (e SynPacketNotFound) Error() string {
	return "Syn Packet not found"
}

func newSynPacketLite(synPacket SynPacket) SynPacketLite {
	return SynPacketLite{ip: synPacket.ip, timeReceived: synPacket.timeReceived}
}

func (db *MemoryDB) saveSynPacket(synPacket SynPacket) {
	db.synPacketMap[synPacket.sequenceNumber] = newSynPacketLite(synPacket)
}

func (db *MemoryDB) getSynPacket(sequenceNumber uint32) (SynPacket, error) {
	syn, isFound := db.synPacketMap[sequenceNumber]

	if isFound {
		return SynPacket{ip: syn.ip, timeReceived: syn.timeReceived, sequenceNumber: sequenceNumber}, nil
	} else {
		return SynPacket{}, SynPacketNotFound{}
	}
}

func (db *MemoryDB) deleteSynPacket(synPacket SynPacket) {
	delete(db.synPacketMap, synPacket.sequenceNumber)
}

func (db *MemoryDB) saveHandshakeTime(handshakeTime HandshakeTime) {
	db.handshakeTimeSlice = append(db.handshakeTimeSlice, handshakeTime)
}

func (db *MemoryDB) getHandshakeTimes() []HandshakeTime {
	return db.handshakeTimeSlice
}

func createMemoryDB() *MemoryDB {
	db := new(MemoryDB)

	db.synPacketMap = make(map[uint32]SynPacketLite)
	return db
}