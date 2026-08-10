package domain

// DeviceSignals contains normalized or HMACed hardware identifiers. Empty
// signals are deliberately incomparable so two collection failures never look
// like the same device.
type DeviceSignals struct {
	TPM         string
	SMBIOS      string
	Motherboard string
	BIOS        string
	SystemDisk  string
	MachineGuid string
}

func ScoreDevice(stored, presented DeviceSignals) int {
	score := 0
	if signalMatches(stored.TPM, presented.TPM) {
		score += 50
	}
	if signalMatches(stored.SMBIOS, presented.SMBIOS) {
		score += 20
	}
	if signalMatches(stored.Motherboard, presented.Motherboard) {
		score += 15
	}
	if signalMatches(stored.BIOS, presented.BIOS) {
		score += 5
	}
	if signalMatches(stored.SystemDisk, presented.SystemDisk) {
		score += 5
	}
	if signalMatches(stored.MachineGuid, presented.MachineGuid) {
		score += 5
	}
	return score
}

func signalMatches(stored, presented string) bool {
	return stored != "" && presented != "" && stored == presented
}
