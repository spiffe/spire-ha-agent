package peertracker

import "net"
import "fmt"
import "github.com/mdlayher/vsock"

func (lf *ListenerFactory) ListenVSock(port uint32) (*Listener, error) {
        if lf.NewUnixListener == nil {
                lf.NewVSockListener = vsock.Listen
        }
        if lf.NewTracker == nil {
                lf.NewTracker = NewTracker
        }
        if lf.Log == nil {
                lf.Log = newNoopLogger()
        }
        return lf.listenVSock(port)
}

func (lf *ListenerFactory) listenVSock(port uint32) (*Listener, error) {
        l, err := lf.NewVSockListener(port, nil)
        if err != nil {
                return nil, err
        }

        tracker, err := lf.NewTracker(lf.Log)
        if err != nil {
                l.Close()
                return nil, err
        }

        return &Listener{
                l:       l,
                Tracker: tracker,
                log:     lf.Log,
        }, nil
}

func CallerFromVSockConn(conn net.Conn) (CallerInfo, error) {
        var info CallerInfo
	cid := int(conn.RemoteAddr().(*vsock.Addr).ContextID)
	pid := CID2PID(cid)
	fmt.Printf("Got PID %d for CID %d\n", pid, cid)
	if pid < 0 {
		return info, fmt.Errorf("Could not fetch PID from CID")
	}
        info = CallerInfo{
                PID: int32(pid),
        }

        info.Addr = conn.RemoteAddr()
        return info, nil
}

