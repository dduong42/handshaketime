package handshaketime

import (
	"net"
	"time"
	"sync"
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
	sync.RWMutex
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

func synPacketFromLite(sequenceNumber uint32, syn SynPacketLite) SynPacket {
	return SynPacket{ip: syn.ip, timeReceived: syn.timeReceived, sequenceNumber: sequenceNumber}
}

func (db *MemoryDB) saveSynPacket(synPacket SynPacket) {
	db.Lock()
	db.synPacketMap[synPacket.sequenceNumber] = newSynPacketLite(synPacket)
	db.Unlock()
}

func (db *MemoryDB) getSynPacket(sequenceNumber uint32) (SynPacket, error) {
	db.RLock()
	syn, isFound := db.synPacketMap[sequenceNumber]
	db.RUnlock()

	if isFound {
		return synPacketFromLite(sequenceNumber, syn), nil
	} else {
		return SynPacket{}, SynPacketNotFound{}
	}
}

func (db *MemoryDB) deleteSynPacket(synPacket SynPacket) {
	db.Lock()
	delete(db.synPacketMap, synPacket.sequenceNumber)
	db.Unlock()
}

func (db *MemoryDB) cleanSynPacket() {
	db.Lock()
	for seqNum, packet := range db.synPacketMap {
		if time.Now().Sub(packet.timeReceived) > time.Second {
			delete(db.synPacketMap, seqNum)
		}
	}
	db.Unlock()
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