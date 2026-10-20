package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"sync"
)

// eventQueue is how many frames a window may fall behind by before it is
// disconnected. Messages go out ten times a second and statistics once, so
// this is many seconds of a window not reading: a frozen one, which will
// reconnect and reload when it recovers. Waiting for it instead would hold up
// the engine that emits.
const eventQueue = 512

// errorType is the type of a method's trailing error result.
var errorType = reflect.TypeOf((*error)(nil)).Elem()

// Server answers the methods of a Host to the windows connected to it, and
// broadcasts what the host's engine emits to all of them. It is the engine's
// event emitter: hand it to the engine, and every window sees what a window
// in the same process would have.
type Server struct {
	methods map[string]reflect.Value
	hello   Hello
	log     *slog.Logger

	mu        sync.Mutex
	conns     map[*serverConn]struct{}
	listeners map[net.Listener]struct{}
	closed    bool
}

// NewServer serves host's methods — those of the Host interface, and no
// other — reporting version in its hello.
func NewServer(host Host, version string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		methods:   map[string]reflect.Value{},
		hello:     Hello{Protocol: ProtocolVersion, Version: version, PID: os.Getpid()},
		log:       log,
		conns:     map[*serverConn]struct{}{},
		listeners: map[net.Listener]struct{}{},
	}
	v := reflect.ValueOf(host)
	t := reflect.TypeOf((*Host)(nil)).Elem()
	for i := 0; i < t.NumMethod(); i++ {
		name := t.Method(i).Name
		s.methods[name] = v.MethodByName(name)
	}
	return s
}

// Serve accepts windows on l until l is closed or the server is.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		l.Close()
		return net.ErrClosed
	}
	s.listeners[l] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.ServeConn(c)
	}
}

// ServeConn talks to one window until it disconnects.
func (s *Server) ServeConn(c net.Conn) {
	sc := newServerConn(c)
	// The hello goes first, queued before the connection can receive any
	// event: a window expects it before anything else.
	sc.out <- mustEncode(frame{Hello: &s.hello})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.Close()
		return
	}
	s.conns[sc] = struct{}{}
	n := len(s.conns)
	s.mu.Unlock()
	s.log.Info("window connected", "windows", n)

	defer func() {
		sc.close()
		s.mu.Lock()
		delete(s.conns, sc)
		n := len(s.conns)
		s.mu.Unlock()
		s.log.Info("window disconnected", "windows", n)
	}()

	go sc.writeLoop()

	dec := json.NewDecoder(c)
	for {
		var f frame
		if err := dec.Decode(&f); err != nil {
			return
		}
		if f.Method == "" || f.ID == 0 {
			continue
		}
		// Each call on its own goroutine: a long query must not hold up the
		// statistics the same window asks for meanwhile.
		go func(f frame) {
			sc.send(mustEncode(s.call(f)))
		}(f)
	}
}

// call runs one request and builds its response. A panic in the engine is
// answered as an error: one bad call must not take the receiver down with it.
func (s *Server) call(f frame) (resp frame) {
	resp.ID = f.ID
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("a call from a window panicked", "method", f.Method, "panic", r)
			resp = frame{ID: f.ID, Error: fmt.Sprintf("%s failed in the service: %v", f.Method, r)}
		}
	}()

	m, ok := s.methods[f.Method]
	if !ok {
		resp.Error = fmt.Sprintf("the service has no method %q", f.Method)
		return resp
	}
	mt := m.Type()
	if len(f.Params) != mt.NumIn() {
		resp.Error = fmt.Sprintf("%s takes %d parameters, not %d", f.Method, mt.NumIn(), len(f.Params))
		return resp
	}
	args := make([]reflect.Value, mt.NumIn())
	for i := range args {
		p := reflect.New(mt.In(i))
		if err := json.Unmarshal(f.Params[i], p.Interface()); err != nil {
			resp.Error = fmt.Sprintf("%s: parameter %d: %v", f.Method, i+1, err)
			return resp
		}
		args[i] = p.Elem()
	}

	out := m.Call(args)
	for i, v := range out {
		if i == len(out)-1 && mt.Out(i) == errorType {
			if !v.IsNil() {
				resp.Error = v.Interface().(error).Error()
			}
			break
		}
		data, err := json.Marshal(v.Interface())
		if err != nil {
			resp.Error = fmt.Sprintf("%s: result %d: %v", f.Method, i+1, err)
			resp.Result = nil
			return resp
		}
		resp.Result = append(resp.Result, data)
	}
	return resp
}

// Emit broadcasts an event to every connected window. It never waits for
// one: a window too far behind is disconnected instead.
func (s *Server) Emit(name string, data ...interface{}) {
	s.mu.Lock()
	if len(s.conns) == 0 {
		s.mu.Unlock()
		return
	}
	conns := make([]*serverConn, 0, len(s.conns))
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	f := frame{Event: name}
	for _, d := range data {
		raw, err := json.Marshal(d)
		if err != nil {
			s.log.Warn("cannot send an event to the windows", "event", name, "error", err)
			return
		}
		f.Data = append(f.Data, raw)
	}
	b := mustEncode(f)
	for _, sc := range conns {
		if !sc.offer(b) {
			s.log.Warn("a window stopped reading; disconnecting it", "event", name)
			sc.close()
		}
	}
}

// Windows is how many windows are connected.
func (s *Server) Windows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Close stops accepting and disconnects every window.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	listeners := s.listeners
	conns := s.conns
	s.listeners = map[net.Listener]struct{}{}
	s.conns = map[*serverConn]struct{}{}
	s.mu.Unlock()
	for l := range listeners {
		l.Close()
	}
	for sc := range conns {
		sc.close()
	}
}

// serverConn is one window's connection. Everything sent to it goes through
// one writer, so frames never interleave.
type serverConn struct {
	c    net.Conn
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func newServerConn(c net.Conn) *serverConn {
	return &serverConn{c: c, out: make(chan []byte, eventQueue), done: make(chan struct{})}
}

func (sc *serverConn) writeLoop() {
	for {
		select {
		case b := <-sc.out:
			if _, err := sc.c.Write(b); err != nil {
				sc.close()
				return
			}
		case <-sc.done:
			return
		}
	}
}

// send queues a response, waiting for room: a window gets every answer it
// asked for, or none because it went away.
func (sc *serverConn) send(b []byte) bool {
	select {
	case sc.out <- b:
		return true
	case <-sc.done:
		return false
	}
}

// offer queues an event if there is room.
func (sc *serverConn) offer(b []byte) bool {
	select {
	case sc.out <- b:
		return true
	case <-sc.done:
		return true
	default:
		return false
	}
}

func (sc *serverConn) close() {
	sc.once.Do(func() {
		close(sc.done)
		sc.c.Close()
	})
}

// mustEncode writes a frame as one line. Frames are built from values that
// already marshalled, so this cannot fail.
func mustEncode(f frame) []byte {
	b, err := json.Marshal(f)
	if err != nil {
		panic(fmt.Sprintf("remote: encode frame: %v", err))
	}
	return append(b, '\n')
}
