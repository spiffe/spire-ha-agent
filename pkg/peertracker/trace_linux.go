package peertracker

import "os/exec"
import "fmt"
import "bytes"
import "gopkg.in/yaml.v3"

// #include <tracefs.h>
//import "C"
/*
func CID2PID(cid int) int {
	pid := int(C.tracefs_find_cid_pid(C.int(cid)))
	return pid

}*/
/*func main() {
	fmt.Printf("%d\n", CID2PID(12345))
}*/

type cid2pid struct {
	Cid int `yaml:"cid"`
	Pid int `yaml:"pid"`
}

func CID2PID(cid int) int {
	buf := new(bytes.Buffer)
	c2p := &cid2pid{}
	cidstr := fmt.Sprintf("%d", cid)
	cmd := exec.Command("cid2pid", cidstr)
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return -1
	}
	err := yaml.Unmarshal(buf.Bytes(), &c2p)
	if err != nil {
		return -4
	}
	if c2p.Cid != cid {
		fmt.Printf("%d %d\n", c2p.Cid, c2p.Pid)
		return -5
	}
	return c2p.Pid
}
