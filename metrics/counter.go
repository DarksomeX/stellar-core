package metrics

import "sync"

type Counter struct {
	total uint64
	sync.RWMutex
}

func (c *Counter) Set(total uint64) {
	c.Lock()
	c.total = total
	c.Unlock()
}

func (c *Counter) Count() uint64 {
	c.Lock()
	defer c.Unlock()

	return c.total
}
