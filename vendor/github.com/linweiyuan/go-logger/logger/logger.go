package logger

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})
}

func ansi(colorString string) func(...interface{}) string {
	return func(args ...interface{}) string {
		return fmt.Sprintf(colorString, fmt.Sprint(args...))
	}
}

var (
	green  = ansi("\033[1;32m%s\033[0m")
	yellow = ansi("\033[1;33m%s\033[0m")
	red    = ansi("\033[1;31m%s\033[0m")
)

//goland:noinspection GoUnusedExportedFunction
func Info(msg string) {
	logrus.Info(green(msg))
}

//goland:noinspection GoUnusedExportedFunction
func Warn(msg string) {
	logrus.Warn(yellow(msg))
}

//goland:noinspection GoUnusedExportedFunction
func Error(msg string) {
	logrus.Error(red(msg))
}
