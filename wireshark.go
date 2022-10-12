package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

type Wireshark struct {
	controlIn  *os.File
	controlOut *os.File
	pcap       io.WriteCloser
	log        *wiresharkLog
}

type wiresharkLog struct {
	w *Wireshark
}

func (w *wiresharkLog) Write(p []byte) (n int, err error) {
	number := 0 // TODO: not always zero

	err = w.w.ControlWrite(byte(number), 2, p)
	if err == nil {
		n = len(p)
	}

	return
}

func (w *Wireshark) Pcap() io.WriteCloser {
	return w.pcap
}

func (w *Wireshark) Log() io.Writer {
	return w.log
}

func (w *Wireshark) ControlWrite(control, command byte, payload []byte) error {
	if len(payload) > 65535 {
		return fmt.Errorf("payload must be 0-65535 bytes")
	}

	buf := &bytes.Buffer{}

	// sync pipe indication (1 byte)
	buf.WriteByte('T')

	// message length (3 bytes)
	msglen := 2 + len(payload)
	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(msglen))
	buf.WriteByte(lenbuf[1])
	buf.WriteByte(lenbuf[2])
	buf.WriteByte(lenbuf[3])

	// control number (1 byte)
	buf.WriteByte(control)

	// command (1 byte)
	buf.WriteByte(command)

	// payload (0 - 64K bytes)
	buf.Write(payload)

	_, err := io.Copy(w.controlOut, buf)
	return err
}

func (w *Wireshark) StatusBar(msg string) {
	err := w.ControlWrite(0, 6, []byte(msg))
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

func handleControlIn(ctlInPipe *os.File) {
	hdr := make([]byte, 6)
	payload := make([]byte, 65535)
	for {
		_, err := io.ReadAtLeast(ctlInPipe, hdr, 6)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			panic(fmt.Sprintf("%+v", err))
		}

		if hdr[0] != 'T' {
			panic("didn't get expected sync pipe indication")
		}

		hdr[0] = 0
		pktlen := binary.BigEndian.Uint32(hdr[0:4]) - 2
		_, err = io.ReadAtLeast(ctlInPipe, payload, int(pktlen))
		if err != nil {
			panic(fmt.Sprintf("%+v", err))
		}

		controlNum := hdr[4]
		command := hdr[5]

		fmt.Fprintf(os.Stderr, "ctrl num=%d command=%d payload=%s\n", controlNum, command, hex.EncodeToString(payload[:pktlen]))
	}
}
