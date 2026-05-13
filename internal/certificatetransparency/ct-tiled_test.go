package certificatetransparency

import (
	"fmt"
	"testing"
)

func Test_encodeTilePath(t *testing.T) {
	tests := []struct {
		name  string
		index uint64
		want  string
	}{
		{
			name:  "zero index",
			index: 0,
			want:  "000",
		},
		{
			name:  "single group padded",
			index: 1,
			want:  "001",
		},
		{
			name:  "single group max",
			index: 999,
			want:  "999",
		},
		{
			name:  "example from spec",
			index: 1_234_067,
			want:  "x001/x234/067",
		},
		{
			name:  "two groups exact thousand",
			index: 1_000,
			want:  "x001/000",
		},
		{
			name:  "two groups with remainder",
			index: 1_001,
			want:  "x001/001",
		},
		{
			name:  "two groups arbitrary",
			index: 123_456,
			want:  "x123/456",
		},
		{
			name:  "three groups",
			index: 1_000_000,
			want:  "x001/x000/000",
		},
		{
			name:  "four groups",
			index: 12_123_456_789,
			want:  "x012/x123/x456/789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeTilePath(tt.index)
			fmt.Println(got, tt.want)
			if got != tt.want {
				t.Errorf("encodeTilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
