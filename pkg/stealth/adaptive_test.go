package stealth

import (
	"testing"
	"time"
)

func TestAdaptiveShaperProfiles(t *testing.T) {
	profiles := []string{"web", "video", "api", "unknown"}

	for _, p := range profiles {
		t.Run("Profile_"+p, func(t *testing.T) {
			shaper := NewAdaptiveShaper(p)
			if shaper == nil {
				t.Fatalf("failed to create adaptive shaper for profile %s", p)
			}

			pad := shaper.SamplePaddingLength(100, 0, 255)
			if pad > 255 {
				t.Errorf("padding out of bounds: %d", pad)
			}

			jitter := shaper.SampleJitter(50 * time.Millisecond)
			if jitter < 0 || jitter > 50*time.Millisecond {
				t.Errorf("jitter out of bounds: %v", jitter)
			}
		})
	}
}
