package domain

import "testing"

func TestScoreThresholdRequiresSeventy(t *testing.T) {
	got := ScoreDevice(
		DeviceSignals{TPM: "t", SMBIOS: "s"},
		DeviceSignals{TPM: "t", SMBIOS: "s"},
	)
	if got != 70 {
		t.Fatalf("score = %d, want 70", got)
	}
}

func TestScoreDeviceBoundaries(t *testing.T) {
	all := DeviceSignals{
		TPM:         "tpm",
		SMBIOS:      "smbios",
		Motherboard: "motherboard",
		BIOS:        "bios",
		SystemDisk:  "disk",
		MachineGuid: "guid",
	}
	tests := []struct {
		name      string
		stored    DeviceSignals
		presented DeviceSignals
		want      int
	}{
		{name: "TPM only is below threshold", stored: DeviceSignals{TPM: "t"}, presented: DeviceSignals{TPM: "t"}, want: 50},
		{name: "all fields", stored: all, presented: all, want: 100},
		{name: "empty values never match", stored: DeviceSignals{}, presented: DeviceSignals{}, want: 0},
		{name: "one empty side never matches", stored: DeviceSignals{TPM: "t", SMBIOS: "s"}, presented: DeviceSignals{TPM: "", SMBIOS: ""}, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ScoreDevice(test.stored, test.presented); got != test.want {
				t.Fatalf("ScoreDevice() = %d, want %d", got, test.want)
			}
		})
	}
}
