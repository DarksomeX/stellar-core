package metrics

import "time"

const tickInterval = 5 * time.Second

type Meter struct {
	count     uint64
	startTime time.Time
	lastTick  time.Time
}

func (m *Meter) Mark(n uint64) {
	m.TickIfNecessary()
}

func (m *Meter) TickIfNecessary() {
	oldTick := m.lastTick
	age := time.Since(oldTick)

	if age > tickInterval {
		m.lastTick = oldTick.Add(age)
	}

	requiredTicks := age / tickInterval
	for i := float64(0); i < requiredTicks.Seconds(); i++ {
		//Tick()
	}
}

//TODO Implement
func (m *Meter) Tick() {

}

func (m *Meter) Update(n uint64) {
	m.TickIfNecessary()
	m.count += n
	//m1Rate.Update(n)
	//m2Rate.Update(n)
	//m3Rate.Update(n)
}
