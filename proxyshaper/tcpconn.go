// Adapted from water/internal/socket/tcpconn.go. Creates a pair of
// connected *net.TCPConn via a localhost loopback listener. Both ends
// have real OS file descriptors, which is required for wazero's
// InsertTCPConn (poll_oneoff needs a kernel-pollable fd).
//
// Both ends have Nagle disabled (TCP_NODELAY) so that small writes
// during the schedule window are pushed immediately rather than
// buffered for up to 200ms.

package proxyshaper

import (
	"fmt"
	"net"
	"sync"
)

func TCPConnPair() (c1, c2 *net.TCPConn, err error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		c2, acceptErr = l.AcceptTCP()
	}()

	c1, err = net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		l.Close()
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	wg.Wait()
	l.Close()
	if acceptErr != nil {
		c1.Close()
		return nil, nil, fmt.Errorf("accept: %w", acceptErr)
	}

	// Disable Nagle on both ends. Without this, small writes during the
	// schedule window can be delayed by up to 200ms (Nagle waits for ACK
	// before sending sub-MSS data), delaying early shaped records.
	c1.SetNoDelay(true)
	c2.SetNoDelay(true)

	return c1, c2, nil
}
