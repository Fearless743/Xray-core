package logx

import (
	"fmt"
	"log"
)

func InstallStd() {}

func Infof(tag, format string, args ...interface{}) {
	log.Printf("[Sudoku][%s] %s", tag, fmt.Sprintf(format, args...))
}

func Warnf(tag, format string, args ...interface{}) {
	log.Printf("[Sudoku][%s] WARN %s", tag, fmt.Sprintf(format, args...))
}

func Errorf(tag, format string, args ...interface{}) {
	log.Printf("[Sudoku][%s] ERR %s", tag, fmt.Sprintf(format, args...))
}

func Debugf(tag, format string, args ...interface{}) {
	log.Printf("[Sudoku][%s] DBG %s", tag, fmt.Sprintf(format, args...))
}

func Fatalf(tag, format string, args ...interface{}) {
	log.Fatalf("[Sudoku][%s] %s", tag, fmt.Sprintf(format, args...))
}
