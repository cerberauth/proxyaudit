package probebase

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"time"
)

const extensionHeartbeat uint16 = 0x000f

const heartbeatOverread = 16

const heartbeatResponseTimeout = 3 * time.Second

func HeartbeatRequest(version uint16) []byte {
	return appendRecord(nil, recordHeartbeat, version, []byte{0x01, 0x00, heartbeatOverread})
}

func ProbeHeartbleed(ctx context.Context, host string) (bool, error) {
	suites := append(slices.Clone(RSASuites), DHESuites...)
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, s.ID)
	}
	slices.Sort(suites)
	suites = slices.Compact(suites)
	hello, err := buildClientHello(VersionTLS12, suites, hostnameOf(host), appendExtension(nil, extensionHeartbeat, []byte{0x01}))
	if err != nil {
		return false, err
	}

	conn, err := dialRaw(ctx, host)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.Write(hello); err != nil {
		return false, err
	}
	flight, err := ReadServerFlight(conn)
	if err != nil {
		if errors.Is(err, ErrHandshakeRejected) {
			return false, nil
		}
		return false, err
	}
	if _, ok := flight.Extensions[extensionHeartbeat]; !ok {
		return false, nil
	}

	if _, err := conn.Write(HeartbeatRequest(flight.Version)); err != nil {
		return false, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(heartbeatResponseTimeout))
	return ReadHeartbeatResponse(conn), nil
}

func ReadHeartbeatResponse(r io.Reader) bool {
	r = io.LimitReader(r, maxLegacyResponse)
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return false
		}
		length := int64(binary.BigEndian.Uint16(header[3:5]))
		switch header[0] {
		case recordHeartbeat:
			_, _ = io.CopyN(io.Discard, r, length)
			return true
		case recordAlert:
			return false
		}
		if _, err := io.CopyN(io.Discard, r, length); err != nil {
			return false
		}
	}
}
