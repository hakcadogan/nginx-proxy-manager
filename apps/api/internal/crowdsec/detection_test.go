package crowdsec

import (
	"strings"
	"testing"
)

func TestDetectionDefaultsAndRender(t *testing.T) {
	s := DefaultDetectionSettings()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	files, err := s.RenderOverrideFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"http-probing.yaml", "http-crawl-non_statics.yaml", "http-generic-bf.yaml", "profiles.yaml"} {
		if files[name] == "" {
			t.Fatalf("missing %s", name)
		}
	}
	if !strings.Contains(files["http-probing.yaml"], "capacity: 10") {
		t.Fatal(files["http-probing.yaml"])
	}
	if !strings.Contains(files["profiles.yaml"], "duration: 4h") {
		t.Fatal(files["profiles.yaml"])
	}
}

func TestDetectionValidateRejectsInjection(t *testing.T) {
	s := DefaultDetectionSettings()
	s.BanDuration = "4h\nevil: true"
	if err := s.Validate(); err == nil {
		t.Fatal("expected reject")
	}
	s = DefaultDetectionSettings()
	s.HTTPProbingCapacity = 0 // normalize fills
	s.Normalize()
	if s.HTTPProbingCapacity != 10 {
		t.Fatal(s.HTTPProbingCapacity)
	}
}
