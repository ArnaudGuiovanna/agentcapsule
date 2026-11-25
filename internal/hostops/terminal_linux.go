package hostops

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(stream any) bool {
	file, ok := stream.(*os.File)
	if !ok || file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}
