package main

import (
	"./handshaketime"
)

func main() {
	handshaketime.StartMonitoring("wlan0")
}