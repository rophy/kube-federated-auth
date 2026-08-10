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

func waitForReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready within 2s", addr)
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

	waitForReady(t, addr)

	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("server not responding: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

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

	waitForReady(t, addr)

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

	<-reqStarted
	cancel()

	select {
	case <-errCh:
		t.Fatal("server exited before in-flight request completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(reqFinish)

	select {
	case status := <-slowDone:
		if status != http.StatusOK {
			t.Fatalf("expected 200 for in-flight request, got %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("listenAndServe returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listenAndServe did not return after draining")
	}
}
