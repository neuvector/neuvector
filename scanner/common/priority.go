package common

// Priority defines a vulnerability priority
type Priority string

const (
	Unknown    Priority = "Unknown"
	Negligible Priority = "Negligible"
	Low        Priority = "Low"
	Medium     Priority = "Medium"
	High       Priority = "High"
	Critical   Priority = "Critical"
	Defcon1    Priority = "Defcon1"
)

var Priorities = []Priority{Unknown, Negligible, Low, Medium, High, Critical, Defcon1}

// Compare compares two priorities
func (p Priority) Compare(p2 Priority) int {
	var i1, i2 int

	for i1 = 0; i1 < len(Priorities); i1 = i1 + 1 {
		if p == Priorities[i1] {
			break
		}
	}
	for i2 = 0; i2 < len(Priorities); i2 = i2 + 1 {
		if p2 == Priorities[i2] {
			break
		}
	}

	return i1 - i2
}
