package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

func TestHighThroughputStressAndKeepAlive(t *testing.T) {
	psk := []byte("test-psk-32bytes-secret-key-stress")
	listenAddr := "127.0.0.1:18445"

	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    listenAddr,
		TransportType: transport.TCP,
		TLSCertFile:   "../../cert.pem",
		TLSKeyFile:    "../../key.pem",
		PSK:           psk,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	srv.OnStream(func(st *stream.Stream) {
		buf := make([]byte, 65536)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				_, _ = st.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	})

	go func() {
		_ = srv.ListenAndServe(context.Background())
	}()
	defer srv.Close()

	time.Sleep(200 * time.Millisecond)

	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:    listenAddr,
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           "example.com",
		Fingerprint:   "chrome",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer clt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := clt.Connect(ctx); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer st.Close()

	// Send 1MB of random data to test throughput under micro-jitter
	dataSize := 1 * 1024 * 1024
	testData := make([]byte, dataSize)
	_, _ = rand.Read(testData)

	start := time.Now()
	errCh := make(chan error, 1)
	receivedData := make([]byte, dataSize)

	go func() {
		_, err := io.ReadFull(st, receivedData)
		errCh <- err
	}()

	chunkSize := 32768
	for i := 0; i < dataSize; i += chunkSize {
		end := i + chunkSize
		if end > dataSize {
			end = dataSize
		}
		if _, err := st.Write(testData[i:end]); err != nil {
			t.Fatalf("Write error at chunk %d: %v", i, err)
		}
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Read full error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Timeout waiting for data transfer")
	}

	elapsed := time.Since(start)
	mbps := (float64(dataSize) / 1024 / 1024) / elapsed.Seconds()
	t.Logf("Transferred 1MB in %v (Speed: %.2f MB/s)", elapsed, mbps)
	fmt.Printf("STRESS TEST PASSED: Transferred 1MB in %v (Speed: %.2f MB/s)\n", elapsed, mbps)

	if !bytes.Equal(testData, receivedData) {
		t.Fatalf("Data mismatch: received data corrupted under high throughput!")
	}
}
