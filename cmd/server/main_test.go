package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestListenAndServe_GracefulShutdown(t *testing.T) {
	addr := freePort(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- listenAndServe(ctx, addr, handler)
	}()

	// Wait for the server to start accepting connections
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify server responds
	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("server not responding: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Cancel context to trigger graceful shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("listenAndServe returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listenAndServe did not return within 5 seconds after context cancellation")
	}
}

func TestListenAndServe_DrainsInFlightRequests(t *testing.T) {
	addr := freePort(t)
	reqStarted := make(chan struct{})
	reqFinish := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(reqStarted)
			<-reqFinish
		}
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- listenAndServe(ctx, addr, handler)
	}()

	// Wait for server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Start an in-flight request
	slowDone := make(chan int, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/slow", addr))
		if err != nil {
			slowDone <- 0
			return
		}
		resp.Body.Close()
		slowDone <- resp.StatusCode
	}()

	// Wait for the slow request to be in-flight, then trigger shutdown
	<-reqStarted
	cancel()

	// Server should NOT have exited yet — the slow request is still in-flight
	select {
	case <-errCh:
		t.Fatal("server exited before in-flight request completed")
	case <-time.After(100 * time.Millisecond):
	}

	// Let the slow request finish
	close(reqFinish)

	// The in-flight request should complete successfully
	select {
	case status := <-slowDone:
		if status != http.StatusOK {
			t.Fatalf("expected 200 for in-flight request, got %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	// Now the server should exit
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("listenAndServe returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listenAndServe did not return after draining")
	}
}
