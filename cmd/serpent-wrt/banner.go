package main

import (
	"io"
	"os"
)

const startupBanner = `                                    __                     __
   ________  _________  ___  ____  / /_     _      _______/ /_
  / ___/ _ \/ ___/ __ \/ _ \/ __ \/ __/____| | /| / / ___/ __/
 (__  )  __/ /  / /_/ /  __/ / / / /_/_____/ |/ |/ / /  / /_
/____/\___/_/  / .___/\___/_/ /_/\__/      |__/|__/_/   \__/
              /_/

lightweight network defense for open platform routers
`

func validBannerMode(mode string) bool {
	switch mode {
	case "auto", "always", "never":
		return true
	default:
		return false
	}
}

func printStartupBanner(w io.Writer, mode string) {
	if shouldPrintStartupBanner(w, mode) {
		writef(w, "%s\n", startupBanner)
	}
}

func shouldPrintStartupBanner(w io.Writer, mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	case "auto":
		return isTerminalWriter(w)
	default:
		return false
	}
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
