package parser

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowguarder/flowguarder/pkg/flow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── table-driven DetectFormat tests ───────────────────────────────────

func TestDetectFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      Source
		wantError bool
	}{
		{
			name:  "hubble verdict field",
			input: `{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"foo"},"destination":{"pod_name":"bar"}}`,
			want:  SourceHubble,
		},
		{
			name:  "calico action field",
			input: `{"start_time":"2024-01-01T00:00:00Z","action":"allow","source_name":"foo","destination_name":"bar"}`,
			want:  SourceCalico,
		},
		{
			name:  "calico syslog starts with <",
			input: `<14>2024-01-01T00:00:00Z host calico[1234]: {"start_time":"2024-01-01T00:00:00Z","action":"allow"}`,
			want:  SourceCalicoSyslog,
		},
		{
			name:      "ambiguous no verdict/no action",
			input:     `{"time":"2024-01-01T00:00:00Z","source":{"pod_name":"foo"},"destination":{"pod_name":"bar"}}`,
			wantError: true,
		},
		{
			name:      "empty input",
			input:     ``,
			wantError: true,
		},
		{
			name:      "whitespace-only input",
			input:     "   \n  \n  ",
			wantError: true,
		},
		{
			name:  "hubble first line with blank lines before",
			input: "\n\n  \n{\"time\":\"2024-01-01T00:00:00Z\",\"verdict\":\"DROPPED\"}",
			want:  SourceHubble,
		},
		{
			name:  "calico first line with blank lines before",
			input: "\n\n{\"start_time\":\"2024-01-01\",\"action\":\"deny\"}",
			want:  SourceCalico,
		},
		{
			name:  "multiple lines — picks first match",
			input: "{\"start_time\":\"2024-01-01\",\"action\":\"allow\"}\n{\"verdict\":\"FORWARDED\"}",
			want:  SourceCalico,
		},
		// ── Goldmane detection ──────────────────────────────────────────────

		{
			name: "goldmane pretty-printed — first non-empty line is just {",
			input: `{
  "flow": {
    "source": {"ip": "10.0.0.1"},
    "destination": {"ip": "10.0.0.2"}
  },
  "sourceName": "hubble-proxy"
}`,
			want: SourceGoldmane,
		},
		{
			name:  "goldmane compact one-line",
			input: `{"flow":{"source":{"ip":"10.0.0.1"},"destination":{"ip":"10.0.0.2"}},"sourceName":"hubble-proxy"}`,
			want:  SourceGoldmane,
		},
		{
			name:  "mixed Hubble first line then Goldmane — Hubble wins",
			input: `{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"foo"},"destination":{"pod_name":"bar"}}
{"flow":{"source":{"ip":"10.0.0.1"},"destination":{"ip":"10.0.0.2"}},"sourceName":"hubble-proxy"}`,
			want: SourceHubble,
		},
		{
			name:  "leading blanks before Goldmane record",
			input: "\n\n   {\"flow\":{\"source\":{\"ip\":\"10.0.0.1\"},\"destination\":{\"ip\":\"10.0.0.2\"}},\"sourceName\":\"hubble-proxy\"}",
			want:  SourceGoldmane,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src, err := DetectFormat(strings.NewReader(tt.input))

			if tt.wantError {
				require.Error(t, err, "expected an error but got none")
				return
			}

			require.NoError(t, err, "unexpected error: %v", err)
			assert.Equal(t, tt.want, src)
		})
	}
}

// ─── DetectFormatFile tests ────────────────────────────────────────────

func TestDetectFormatFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	hubbleFile := filepath.Join(tmpDir, "hubble.json")
	require.NoError(t, os.WriteFile(hubbleFile, []byte(`{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED","source":{"pod_name":"foo"},"destination":{"pod_name":"bar"}}`), 0644))

	calicoFile := filepath.Join(tmpDir, "calico.json")
	require.NoError(t, os.WriteFile(calicoFile, []byte(`{"start_time":"2024-01-01T00:00:00Z","action":"allow","source_name":"foo","destination_name":"bar"}`), 0644))

	syslogFile := filepath.Join(tmpDir, "syslog.log")
	require.NoError(t, os.WriteFile(syslogFile, []byte(`<14>2024-01-01T00:00:00Z host calico[1234]: {"start_time":"2024-01-01","action":"deny"}`), 0644))

	tests := []struct {
		name      string
		file      string
		want      Source
		wantError bool
	}{
		{name: "hubble json file", file: hubbleFile, want: SourceHubble},
		{name: "calico json file", file: calicoFile, want: SourceCalico},
		{name: "calico syslog file", file: syslogFile, want: SourceCalicoSyslog},
		{name: "nonexistent file", file: filepath.Join(tmpDir, "nope.json"), wantError: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src, err := DetectFormatFile(tt.file)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, src)
		})
	}
}

// ─── DetectFormatDir tests ─────────────────────────────────────────────

func TestDetectFormatDir(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create hubble file — alphabetically first.
	hubbleFile := filepath.Join(tmpDir, "001_hubble.json")
	require.NoError(t, os.WriteFile(hubbleFile, []byte(`{"time":"2024-01-01T00:00:00Z","verdict":"FORWARDED"}`), 0644))

	// Create calico file.
	_ = filepath.Join(tmpDir, "002_calico.json")
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "002_calico.json"), []byte(`{"start_time":"2024-01-01T00:00:00Z","action":"allow"}`), 0644))

	// Create a non-matching file.
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0644))

	t.Run("detects first matching file", func(t *testing.T) {
		src, err := DetectFormatDir(tmpDir)
		require.NoError(t, err)
		assert.Equal(t, SourceHubble, src)
	})

	// Create an empty dir.
	emptyDir := t.TempDir()
	t.Run("empty dir returns error", func(t *testing.T) {
		_, err := DetectFormatDir(emptyDir)
		require.Error(t, err)
	})

	// Create a dir with only non-matching files.
	otherDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(otherDir, "readme.txt"), []byte("text"), 0644))
	t.Run("no matching files returns error", func(t *testing.T) {
		_, err := DetectFormatDir(otherDir)
		require.Error(t, err)
	})

	// Create a dir with nonexistent path.
	t.Run("nonexistent dir returns error", func(t *testing.T) {
		_, err := DetectFormatDir(filepath.Join(tmpDir, "nope"))
		require.Error(t, err)
	})
}

type _testHubbleParser struct{}

func (p *_testHubbleParser) Parse(r io.Reader, emit func(flow.Flow) error) error { return nil }
func (p *_testHubbleParser) Source() Source { return SourceHubble }

type _testCalicoParser struct{}

func (p *_testCalicoParser) Parse(r io.Reader, emit func(flow.Flow) error) error { return nil }
func (p *_testCalicoParser) Source() Source { return SourceCalico }

type _testCalicoSyslogParser struct{}

func (p *_testCalicoSyslogParser) Parse(r io.Reader, emit func(flow.Flow) error) error { return nil }
func (p *_testCalicoSyslogParser) Source() Source { return SourceCalicoSyslog }

// ─── SelectParser tests ────────────────────────────────────────────────

func TestSelectParser(t *testing.T) {
	// Register test parsers since init() from subpackages doesn't run
	// during unit tests of the parent parser package.
	RegisterParser(SourceHubble, func() Parser { return &_testHubbleParser{} })
	defer delete(parserRegistry, SourceHubble)
	RegisterParser(SourceCalico, func() Parser { return &_testCalicoParser{} })
	defer delete(parserRegistry, SourceCalico)
	RegisterParser(SourceCalicoSyslog, func() Parser { return &_testCalicoSyslogParser{} })
	defer delete(parserRegistry, SourceCalicoSyslog)

	tests := []struct {
		name      string
		src       Source
		override  Source
		want      Source
		wantError bool
	}{
		{name: "override auto with hubble detected", src: SourceHubble, override: SourceAuto, want: SourceHubble},
		{name: "override auto with calico detected", src: SourceCalico, override: SourceAuto, want: SourceCalico},
		{name: "override auto with calico syslog detected", src: SourceCalicoSyslog, override: SourceAuto, want: SourceCalicoSyslog},
		{name: "override with hubble overrides calico detection", src: SourceCalico, override: SourceHubble, want: SourceHubble},
		{name: "override with calico overrides hubble detection", src: SourceHubble, override: SourceCalico, want: SourceCalico},
		{name: "override calico syslog overrides everything", src: SourceHubble, override: SourceCalicoSyslog, want: SourceCalicoSyslog},
		{name: "detect unknown source returns error", src: SourceUnknown, override: SourceAuto, wantError: true},
		{name: "override to unknown returns error", src: SourceCalico, override: SourceUnknown, wantError: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := SelectParser(tt.src, tt.override)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			// Verify the resolved source matches expectation.
			got := resolver.Source()
			assert.Equal(t, tt.want, got)
		})
	}
}

// ─── Edge cases ────────────────────────────────────────────────────────

func TestDetectFormatEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("key buried in string value has real verdict detected", func(t *testing.T) {
		// "action" as a substring of a key name shouldn't block
		// detection of "verdict" — both are present, verdict is first keyword.
		src, err := DetectFormat(strings.NewReader(`{"comment":"not an action","verdict":"FORWARDED"}`))
		require.NoError(t, err)
		assert.Equal(t, SourceHubble, src)
	})

	t.Run("nonexistent file error wraps path", func(t *testing.T) {
		_, err := DetectFormatFile("/no/such/file.json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/no/such/file.json")
	})
}

// ─── DetectFormat wraps ErrAmbiguous in FormatError ────────────────────

func TestDetectFormatAmbiguousIsFormatError(t *testing.T) {
	t.Parallel()

	// An ambiguous line should return a FormatError wrapping ErrAmbiguous.
	src, err := DetectFormat(strings.NewReader(`{"time":"2024-01-01T00:00:00Z","source":{"pod_name":"x"},"destination":{"pod_name":"y"}}`))
	require.Error(t, err)
	_, ok := err.(*FormatError)
	assert.True(t, ok, "expected error to be *FormatError, got %T", err)
	assert.Equal(t, SourceUnknown, src)
}
