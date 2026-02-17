package dbaudit

import (
	"encoding/json"
	"sync"
)

// Collector accumulates QueryEvents during a session and serializes
// them as a JSON array when the session closes.
type Collector struct {
	mu     sync.Mutex
	events []QueryEvent
}

// NewCollector creates a new query event collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Add appends a query event to the collection.
func (c *Collector) Add(ev QueryEvent) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

// Count returns the number of collected events.
func (c *Collector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// Recording serializes all collected events as a JSON array string.
// Returns an empty string if no events were collected.
func (c *Collector) Recording() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.events) == 0 {
		return ""
	}

	data, err := json.Marshal(c.events)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// RunCollector reads events from the channel and adds them to the collector.
// Stops when the channel is closed.
func RunCollector(collector *Collector, events <-chan QueryEvent) {
	for ev := range events {
		collector.Add(ev)
	}
}
