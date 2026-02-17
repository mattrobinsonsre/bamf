package dbaudit

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// connPair creates a connected pair of net.Conns for testing.
func connPair() (net.Conn, net.Conn) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	client, _ := net.Dial("tcp", ln.Addr().String())
	server := <-ch
	ln.Close()
	return client, server
}

func TestIntegration_PostgresPipeline(t *testing.T) {
	// Simulates: client → TeeReader → agent
	// The TeeReader taps the client→agent stream and extracts queries.
	clientSend, clientRecv := connPair()
	defer clientSend.Close()
	defer clientRecv.Close()

	// Build PostgreSQL byte stream.
	var pgData bytes.Buffer

	// Startup message.
	startup := make([]byte, 9)
	binary.BigEndian.PutUint32(startup[0:4], 9)
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	startup[8] = 0
	pgData.Write(startup)

	// Two queries.
	queries := []string{"SELECT version()", "INSERT INTO test VALUES (1, 'hello')"}
	for _, sql := range queries {
		payload := append([]byte(sql), 0)
		msg := make([]byte, 1+4+len(payload))
		msg[0] = 'Q'
		binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
		copy(msg[5:], payload)
		pgData.Write(msg)
	}

	expectedData := pgData.Bytes()

	// Set up tee pipeline.
	eventCh := make(chan QueryEvent, 100)
	collector := NewCollector()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RunCollector(collector, eventCh)
	}()

	parser := NewPostgresParser()
	tee := NewTeeReader(clientRecv, parser, eventCh)

	// Write data from the "client" side.
	go func() {
		_, _ = clientSend.Write(expectedData)
		clientSend.Close()
	}()

	// Read from the tee (simulates agent reading).
	got, err := io.ReadAll(tee)
	require.NoError(t, err)
	require.Equal(t, expectedData, got, "data should pass through unchanged")

	// Close event channel and wait for collector to finish draining.
	close(eventCh)
	wg.Wait()

	require.Equal(t, 2, collector.Count())

	recording := collector.Recording()
	require.NotEmpty(t, recording)
	require.Contains(t, recording, "SELECT version()")
	require.Contains(t, recording, "INSERT INTO test VALUES")
}

func TestIntegration_MySQLPipeline(t *testing.T) {
	clientSend, clientRecv := connPair()
	defer clientSend.Close()
	defer clientRecv.Close()

	var mysqlData bytes.Buffer

	// Client auth response (will be skipped by parser).
	authPayload := make([]byte, 32)
	authPayload[0] = 0x85 // some capability flags
	authPkt := make([]byte, 4+len(authPayload))
	authPkt[0] = byte(len(authPayload))
	authPkt[1] = byte(len(authPayload) >> 8)
	authPkt[2] = byte(len(authPayload) >> 16)
	authPkt[3] = 1 // seq
	copy(authPkt[4:], authPayload)
	mysqlData.Write(authPkt)

	// COM_QUERY packets.
	queries := []string{"SHOW TABLES", "SELECT * FROM users"}
	for _, sql := range queries {
		payload := append([]byte{mysqlComQuery}, []byte(sql)...)
		pkt := make([]byte, 4+len(payload))
		pkt[0] = byte(len(payload))
		pkt[1] = byte(len(payload) >> 8)
		pkt[2] = byte(len(payload) >> 16)
		pkt[3] = 0
		copy(pkt[4:], payload)
		mysqlData.Write(pkt)
	}

	expectedData := mysqlData.Bytes()

	eventCh := make(chan QueryEvent, 100)
	collector := NewCollector()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RunCollector(collector, eventCh)
	}()

	parser := NewMySQLParser()
	tee := NewTeeReader(clientRecv, parser, eventCh)

	go func() {
		_, _ = clientSend.Write(expectedData)
		clientSend.Close()
	}()

	got, err := io.ReadAll(tee)
	require.NoError(t, err)
	require.Equal(t, expectedData, got)

	close(eventCh)
	wg.Wait()

	require.Equal(t, 2, collector.Count())

	recording := collector.Recording()
	require.Contains(t, recording, "SHOW TABLES")
	require.Contains(t, recording, "SELECT * FROM users")
}
