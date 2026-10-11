// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"sync"
)

// Store is a thread-safe ring buffer of traffic entries with SSE broadcast support.
type Store struct {
	mu         sync.RWMutex
	entries    []*TrafficEntry
	maxSize    int
	nextID     int64
	nextFlowID int64
	flows      map[string]string // correlation key → flow ID
	// A flow's keys live as long as any of its entries is in the buffer.
	flowKeys    map[string][]string
	flowEntries map[string]int
	subscribers map[int64]chan *TrafficEntry
	subID       int64
}

func NewStore(maxSize int) *Store {
	return &Store{
		maxSize:     maxSize,
		entries:     make([]*TrafficEntry, 0, maxSize),
		flows:       make(map[string]string),
		flowKeys:    make(map[string][]string),
		flowEntries: make(map[string]int),
		subscribers: make(map[int64]chan *TrafficEntry),
	}
}

func (s *Store) Add(entry *TrafficEntry) {
	s.mu.Lock()
	s.nextID++
	entry.ID = s.nextID

	if keys := ExtractCorrelationKeys(entry); len(keys) > 0 {
		for _, key := range keys {
			if flowID, ok := s.flows[key]; ok {
				entry.FlowID = flowID
				break
			}
		}
		if entry.FlowID == "" {
			s.nextFlowID++
			entry.FlowID = fmt.Sprintf("flow-%d", s.nextFlowID)
		}
		for _, key := range keys {
			if s.flows[key] != entry.FlowID {
				s.flows[key] = entry.FlowID
				s.flowKeys[entry.FlowID] = append(s.flowKeys[entry.FlowID], key)
			}
		}
		s.flowEntries[entry.FlowID]++
	}

	if len(s.entries) >= s.maxSize {
		s.evictOldest()
	}
	s.entries = append(s.entries, entry)
	subs := make([]chan *TrafficEntry, 0, len(s.subscribers))
	for _, ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	// Notification runs outside the lock, so a slow subscriber blocks nothing.
	for _, ch := range subs {
		select {
		case ch <- entry:
		default:
			// A slow subscriber misses the entry.
		}
	}
}

func (s *Store) evictOldest() {
	evicted := s.entries[0]
	s.entries = s.entries[1:]
	flowID := evicted.FlowID
	if flowID == "" {
		return
	}
	s.flowEntries[flowID]--
	if s.flowEntries[flowID] > 0 {
		return
	}
	for _, key := range s.flowKeys[flowID] {
		// A later entry can move a key to the flow it joined.
		if s.flows[key] == flowID {
			delete(s.flows, key)
		}
	}
	delete(s.flowKeys, flowID)
	delete(s.flowEntries, flowID)
}

// MaxSize is how many entries the store keeps.
func (s *Store) MaxSize() int { return s.maxSize }

func (s *Store) Entries() []*TrafficEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TrafficEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

func (s *Store) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subscribers)
}

// Subscribe returns a channel that receives new traffic entries and an unsubscribe function.
func (s *Store) Subscribe() (<-chan *TrafficEntry, func()) {
	ch := make(chan *TrafficEntry, 64)
	s.mu.Lock()
	s.subID++
	id := s.subID
	s.subscribers[id] = ch
	s.mu.Unlock()

	unsub := func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			default:
				return
			}
		}
	}
	return ch, unsub
}
