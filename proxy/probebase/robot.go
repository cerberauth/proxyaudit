package probebase

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
)

var RSASuites = []uint16{0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d, 0x000a}

var ErrNoRSAKeyExchange = errors.New("server does not negotiate RSA key exchange")

var robotResponseTimeout = 3 * time.Second

const (
	robotCorrectPadding = iota
	robotWrongPrefix
	robotMisplacedZero
	robotMissingZero
	robotWrongVersion
	robotVariants
)

func RobotPremasterSecrets(size int) ([][]byte, error) {
	padLength := size - 3 - 48
	if padLength < 8 {
		return nil, errors.New("rsa modulus too small")
	}
	padding := bytes.Repeat([]byte{0xab, 0xcd}, padLength/2+1)[:padLength]
	secret := bytes.Repeat([]byte{0x11, 0x22, 0x33}, 16)[:46]

	build := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	variants := make([][]byte, robotVariants)
	variants[robotCorrectPadding] = build([]byte{0x00, 0x02}, padding, []byte{0x00, 0x03, 0x03}, secret)
	variants[robotWrongPrefix] = build([]byte{0x41, 0x17}, padding, []byte{0x00, 0x03, 0x03}, secret)
	variants[robotMisplacedZero] = build([]byte{0x00, 0x02}, padding, []byte{0x11}, secret, []byte{0x00, 0x11})
	variants[robotMissingZero] = build([]byte{0x00, 0x02}, padding, []byte{0x11, 0x11, 0x11}, secret)
	variants[robotWrongVersion] = build([]byte{0x00, 0x02}, padding, []byte{0x00, 0x02, 0x02}, secret)
	return variants, nil
}

func encryptRaw(key *rsa.PublicKey, message []byte) []byte {
	c := new(big.Int).Exp(new(big.Int).SetBytes(message), big.NewInt(int64(key.E)), key.N)
	return c.FillBytes(make([]byte, key.Size()))
}

func RobotClientFlight(version uint16, key *rsa.PublicKey, premaster []byte, finished bool) []byte {
	encrypted := encryptRaw(key, premaster)
	body := appendUint16(nil, uint16(len(encrypted))) //nolint:gosec
	body = append(body, encrypted...)
	message := append([]byte{handshakeClientKeyExchange}, appendUint24(nil, len(body))...)
	message = append(message, body...)

	flight := appendRecord(nil, recordHandshake, version, message)
	if finished {
		flight = appendRecord(flight, recordChangeCipherSpec, version, []byte{0x01})
		flight = appendRecord(flight, recordHandshake, version, bytes.Repeat([]byte{0x07}, 40))
	}
	return flight
}

func rsaKey(flight *ServerFlight) (*rsa.PublicKey, error) {
	if !slices.Contains(RSASuites, flight.CipherSuite) || len(flight.Certificates) == 0 {
		return nil, ErrNoRSAKeyExchange
	}
	cert, err := x509.ParseCertificate(flight.Certificates[0])
	if err != nil {
		return nil, err
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNoRSAKeyExchange
	}
	return key, nil
}

func robotOracle(ctx context.Context, host string, variant int, finished bool) (string, error) {
	hello, err := BuildClientHello(VersionTLS12, RSASuites, hostnameOf(host))
	if err != nil {
		return "", err
	}
	conn, err := dialRaw(ctx, host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := conn.Write(hello); err != nil {
		return "", err
	}
	flight, err := ReadServerFlight(conn)
	if err != nil {
		if errors.Is(err, ErrHandshakeRejected) {
			return "", ErrNoRSAKeyExchange
		}
		return "", err
	}
	key, err := rsaKey(flight)
	if err != nil {
		return "", err
	}
	premasters, err := RobotPremasterSecrets(key.Size())
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(RobotClientFlight(flight.Version, key, premasters[variant], finished)); err != nil {
		return "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(robotResponseTimeout))
	return ReadOracleResponse(conn), nil
}

func ReadOracleResponse(r io.Reader) string {
	header := make([]byte, 5)
	_, err := io.ReadFull(r, header)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "timeout"
		}
		return "error"
	}
	if header[0] != recordAlert {
		return fmt.Sprintf("record %d", header[0])
	}
	alert := make([]byte, 2)
	if binary.BigEndian.Uint16(header[3:5]) < 2 {
		return "alert"
	}
	if _, err := io.ReadFull(r, alert); err != nil {
		return "alert"
	}
	return fmt.Sprintf("alert %d %d", alert[0], alert[1])
}

func robotRound(ctx context.Context, host string, finished bool) ([]string, error) {
	responses := make([]string, robotVariants)
	errs := make([]error, robotVariants)
	var wg sync.WaitGroup
	for variant := range robotVariants {
		wg.Go(func() {
			responses[variant], errs[variant] = robotOracle(ctx, host, variant, finished)
		})
	}
	wg.Wait()
	return responses, errors.Join(errs...)
}

type RobotResult struct {
	Vulnerable bool
	Responses  []string
}

func ProbeROBOT(ctx context.Context, host string) (*RobotResult, error) {
	for _, finished := range []bool{true, false} {
		first, err := robotRound(ctx, host, finished)
		if err != nil {
			if errors.Is(err, ErrNoRSAKeyExchange) {
				return &RobotResult{}, nil
			}
			return nil, err
		}
		if !slices.ContainsFunc(first, func(r string) bool { return r != first[robotCorrectPadding] }) {
			continue
		}
		second, err := robotRound(ctx, host, finished)
		if err != nil {
			return nil, err
		}
		return &RobotResult{Vulnerable: slices.Equal(first, second), Responses: first}, nil
	}
	return &RobotResult{}, nil
}
