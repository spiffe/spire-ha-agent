package peertracker

import (
	"github.com/mdlayher/vsock"
)

func (lf *ListenerFactory) ListenVSock(port uint32) (*Listener, error) {
	if _, err := os.Stat("/dev/vsock"); err != nil {
		return nil, err
	}
	if lf.NewVSockListener == nil {
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
