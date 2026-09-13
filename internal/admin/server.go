package admin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Handler answers admin requests. The daemon implements it; the socket plumbing here
// does not know what any command means.
type Handler interface {
	Handle(Request) Response
}

// Server accepts admin connections on a unix socket.
//
// The socket is created at 0600 inside the data directory, which is the whole access
// control story: if you can open the socket you are the user who owns the node. There
// is no authentication because there is no remote access — the socket never leaves the
// machine, so there is no credential to steal and no network path to reach it over.
type Server struct {
	path     string
	handler  Handler
	listener net.Listener

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

// Listen creates the socket and starts accepting.
//
// A stale socket left by a killed daemon is removed first, but only after checking
// that nothing is listening on it. Removing a live socket would silently steal control
// of a running daemon, which is a considerably worse outcome than refusing to start.
func Listen(dir string, handler Handler) (*Server, error) {
	path := filepath.Join(dir, SocketName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("admin: create dir: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		conn, err := net.Dial("unix", path)
		if err == nil {
			conn.Close()
			return nil, fmt.Errorf("admin: a daemon is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("admin: remove stale socket: %w", err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("admin: chmod socket: %w", err)
	}

	s := &Server{path: path, handler: handler, listener: ln, conns: make(map[net.Conn]struct{})}
	go s.accept()
	return s, nil
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

func (s *Server) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.serve(conn)
	}
}

// serve handles one connection: newline-delimited JSON requests and responses, so a
// client can hold the connection open for --watch without reconnecting.
func (s *Server) serve(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4<<10), 1<<20)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(Response{Protocol: Protocol, Error: fmt.Sprintf("malformed request: %v", err)})
			continue
		}
		if req.Protocol != 0 && req.Protocol != Protocol {
			_ = enc.Encode(Response{
				Protocol: Protocol,
				Error: fmt.Sprintf("memctl speaks admin protocol %d, this daemon speaks %d; upgrade whichever is older",
					req.Protocol, Protocol),
			})
			continue
		}
		resp := s.handler.Handle(req)
		resp.Protocol = Protocol
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

// Close stops accepting and removes the socket.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	err := s.listener.Close()
	for conn := range conns {
		conn.Close()
	}
	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	return err
}

// Client talks to a local daemon's admin socket.
type Client struct {
	conn    net.Conn
	scanner *bufio.Scanner
	enc     *json.Encoder
}

// ErrNoDaemon reports that nothing is listening. Distinguished from other failures
// because it is by far the most common one and has a specific remedy.
var ErrNoDaemon = errors.New("admin: no daemon is listening")

// Dial connects to the daemon in a data directory.
func Dial(dir string) (*Client, error) {
	path := filepath.Join(dir, SocketName)
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w at %s: %v", ErrNoDaemon, path, err)
	}
	c := &Client{conn: conn, enc: json.NewEncoder(conn)}
	c.scanner = bufio.NewScanner(conn)
	c.scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
	return c, nil
}

// Do sends a request and reads one response.
func (c *Client) Do(req Request) (*Response, error) {
	req.Protocol = Protocol
	if err := c.enc.Encode(req); err != nil {
		return nil, fmt.Errorf("admin: send: %w", err)
	}
	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return nil, fmt.Errorf("admin: read: %w", err)
		}
		return nil, errors.New("admin: daemon closed the connection")
	}
	var resp Response
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("admin: parse response: %w", err)
	}
	if resp.Error != "" {
		return &resp, fmt.Errorf("memd: %s", resp.Error)
	}
	return &resp, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }
