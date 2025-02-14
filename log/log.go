/*
Package log provides support for logging to stdout and stderr.

Log entries will be logged in the following format:

    SEVERITY Message
*/
package log

import (
	"fmt"
	"os"
	"strings"
	
	log "github.com/sirupsen/logrus"
)

type LogFormatter struct {
}

func (c *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s %s\n", strings.ToUpper(entry.Level.String()), entry.Message)), nil
}

// tag represents the application name generating the log message. The tag
// string will appear in all log entires.
var tag string

func init() {
	tag = os.Args[0]
	log.SetFormatter(&LogFormatter{})
}

// SetTag sets the tag.
func SetTag(t string) {
	tag = t
}

// SetLevel sets the log level. Valid levels are panic, fatal, error, warn, info and debug.
func SetLevel(level string) {
	lvl, err := log.ParseLevel(level)
	if err != nil {
		Fatal(fmt.Sprintf(`not a valid level: "%s"`, level))
	}
	log.SetLevel(lvl)
}

func IsDebugEnable() bool {
	return log.GetLevel() >= log.DebugLevel
}

// Debug logs a message with severity DEBUG.
func Debug(format string, v ...interface{}) {
	log.Debug(fmt.Sprintf(format, v...))
}

// Error logs a message with severity ERROR.
func Error(format string, v ...interface{}) {
	log.Error(fmt.Sprintf(format, v...))
}

// Fatal logs a message with severity ERROR followed by a call to os.Exit().
func Fatal(format string, v ...interface{}) {
	log.Fatal(fmt.Sprintf(format, v...))
}

// Info logs a message with severity INFO.
func Info(format string, v ...interface{}) {
	log.Info(fmt.Sprintf(format, v...))
}

// Warning logs a message with severity WARNING.
func Warning(format string, v ...interface{}) {
	log.Warning(fmt.Sprintf(format, v...))
}
