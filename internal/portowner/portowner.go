// Package portowner finds which program holds a local port, so a listener
// that cannot open can say who has its port: "address already in use" alone
// sends people looking for the culprit.
package portowner

import "fmt"

// Owner is a process holding a port.
type Owner struct {
	PID uint32
	// Name is its executable's file name, empty when it could not be read.
	Name string
}

func (o Owner) String() string {
	if o.Name == "" {
		return fmt.Sprintf("process %d", o.PID)
	}
	return fmt.Sprintf("%s (PID %d)", o.Name, o.PID)
}
