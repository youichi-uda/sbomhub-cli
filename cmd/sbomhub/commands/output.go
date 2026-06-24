package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// OutputConfig holds output configuration derived from global flags
type OutputConfig struct {
	Quiet   bool
	Verbose bool
	JSON    bool
	Writer  io.Writer
	ErrWriter io.Writer
}

// globalOutput is the shared output configuration
var globalOutput = &OutputConfig{
	Writer:    os.Stdout,
	ErrWriter: os.Stderr,
}

// GetOutputConfig returns the current output configuration
func GetOutputConfig() *OutputConfig {
	return globalOutput
}

// InitOutputConfig initializes output configuration from global flags
func InitOutputConfig(quiet, verbose, jsonOutput bool) {
	globalOutput.Quiet = quiet
	globalOutput.Verbose = verbose
	globalOutput.JSON = jsonOutput
}

// humanWriter returns the writer for human-readable output. In JSON
// mode it returns ErrWriter (typically os.Stderr) so that stdout is
// reserved exclusively for the JSON payload — otherwise the human-
// friendly progress lines would corrupt downstream `jq` consumers.
// Outside of JSON mode it returns Writer (typically os.Stdout) as
// before.
func (o *OutputConfig) humanWriter() io.Writer {
	if o.JSON {
		return o.ErrWriter
	}
	return o.Writer
}

// Print prints a message (respects quiet mode). Routes to stderr in
// JSON mode so stdout stays clean for the JSON payload.
func (o *OutputConfig) Print(format string, args ...interface{}) {
	if o.Quiet {
		return
	}
	fmt.Fprintf(o.humanWriter(), format, args...)
}

// Println prints a message with newline (respects quiet mode). Routes
// to stderr in JSON mode so stdout stays clean for the JSON payload.
func (o *OutputConfig) Println(args ...interface{}) {
	if o.Quiet {
		return
	}
	fmt.Fprintln(o.humanWriter(), args...)
}

// PrintSuccess prints a success message (respects quiet mode). Routes
// to stderr in JSON mode so stdout stays clean for the JSON payload.
func (o *OutputConfig) PrintSuccess(format string, args ...interface{}) {
	if o.Quiet {
		return
	}
	fmt.Fprintf(o.humanWriter(), "✓ "+format+"\n", args...)
}

// PrintInfo prints an info message (respects quiet mode). Routes to
// stderr in JSON mode so stdout stays clean for the JSON payload.
func (o *OutputConfig) PrintInfo(format string, args ...interface{}) {
	if o.Quiet {
		return
	}
	fmt.Fprintf(o.humanWriter(), format+"\n", args...)
}

// PrintVerbose prints a verbose message (only in verbose mode). Routes
// to stderr in JSON mode so stdout stays clean for the JSON payload.
func (o *OutputConfig) PrintVerbose(format string, args ...interface{}) {
	if !o.Verbose {
		return
	}
	fmt.Fprintf(o.humanWriter(), "[DEBUG] "+format+"\n", args...)
}

// PrintError prints an error message (always printed)
func (o *OutputConfig) PrintError(format string, args ...interface{}) {
	fmt.Fprintf(o.ErrWriter, "Error: "+format+"\n", args...)
}

// PrintJSON prints data as JSON
func (o *OutputConfig) PrintJSON(data interface{}) error {
	encoder := json.NewEncoder(o.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// PrintResult prints a result, using JSON if --json flag is set
func (o *OutputConfig) PrintResult(data interface{}, humanFormat func()) error {
	if o.JSON {
		return o.PrintJSON(data)
	}
	if !o.Quiet {
		humanFormat()
	}
	return nil
}

// ShouldPrint returns whether output should be printed
func (o *OutputConfig) ShouldPrint() bool {
	return !o.Quiet
}

// IsJSON returns whether JSON output is requested
func (o *OutputConfig) IsJSON() bool {
	return o.JSON
}

// IsVerbose returns whether verbose mode is enabled
func (o *OutputConfig) IsVerbose() bool {
	return o.Verbose
}
