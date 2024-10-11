package system

import (
	"time"

	"github.com/neuvector/neuvector/share"
)

func calculateCPU(prevCPU, prevCPUSystem uint64, cpu, cpuSystem uint64) float64 {
	var cDelta float64 = float64(cpu - prevCPU)
	var sDelta float64 = float64(cpuSystem - prevCPUSystem)

	if sDelta > 0.0 {
		if cDelta > sDelta {
			return 1
		} else {
			return cDelta / sDelta
		}
	}

	return 0
}

func UpdateStats(cs *share.ContainerStats, memory, cpu, cpuSystem uint64) {
	ratio := calculateCPU(cs.PrevCPU, cs.PrevCPUSystem, cpu, cpuSystem)
	cs.PrevCPU = cpu
	cs.PrevCPUSystem = cpuSystem

	cs.ReadAt = time.Now().UTC()
	cs.Cpu[cs.CurSlot] = ratio
	cs.Memory[cs.CurSlot] = memory

	cs.CurSlot++
	if cs.CurSlot == share.ContainerStatsSlots {
		cs.CurSlot = 0
	}
}

func PopulateSystemStats(data *share.CLUSStats, stats *share.ContainerStats) {
	var s uint
	var cpu float64
	var memory uint64

	s = (stats.CurSlot + share.ContainerStatsSlots - 1) % share.ContainerStatsSlots
	data.Span1.CPU = stats.Cpu[s]
	data.Span1.Memory = stats.Memory[s]

	cpu = 0
	memory = 0
	s = (stats.CurSlot + share.ContainerStatsSlots - 12) % share.ContainerStatsSlots
	for n := 0; n < 12; n++ {
		cpu += stats.Cpu[s]
		memory += stats.Memory[s]
		s = (s + 1) % share.ContainerStatsSlots
	}
	data.Span12.CPU = cpu / 12
	data.Span12.Memory = memory / 12

	cpu = 0
	memory = 0
	s = (stats.CurSlot + share.ContainerStatsSlots - 59) % share.ContainerStatsSlots
	for n := 0; n < 59; n++ {
		cpu += stats.Cpu[s]
		memory += stats.Memory[s]
		s = (s + 1) % share.ContainerStatsSlots
	}
	data.Span60.CPU = cpu / 59
	data.Span60.Memory = memory / 59
}
