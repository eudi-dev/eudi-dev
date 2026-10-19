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

package browserlaunch

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// callTimeout bounds one Chrome DevTools Protocol command.
const callTimeout = 30 * time.Second

// errBrowserClosed reports that the browser closed the pipe. A browser started
// on a profile that a running browser already uses opens its window there and
// exits.
var errBrowserClosed = errors.New("the browser closed the connection. Another browser window may already use the eudi-dev profile, so close it and try again")

// cdpClient sends Chrome DevTools Protocol commands over the pipe of
// --remote-debugging-pipe. Each message is JSON followed by a NUL byte.
type cdpClient struct {
	writeMu sync.Mutex
	w       io.Writer

	mu      sync.Mutex
	nextID  int
	pending map[int]chan cdpResponse
	done    chan struct{}
}

type cdpResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newCDPClient(w io.Writer, r io.Reader) *cdpClient {
	c := &cdpClient{w: w, pending: map[int]chan cdpResponse{}, done: make(chan struct{})}
	go c.read(r)
	return c
}

// read passes each response to its caller and ignores events. It keeps reading
// until the browser exits, so the browser never blocks on a full pipe.
func (c *cdpClient) read(r io.Reader) {
	defer close(c.done)
	br := bufio.NewReader(r)
	for {
		msg, err := br.ReadBytes(0)
		if err != nil {
			return
		}
		var resp cdpResponse
		if json.Unmarshal(msg[:len(msg)-1], &resp) != nil || resp.ID == 0 {
			continue
		}
		c.mu.Lock()
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
}

// call sends a command and decodes its result into result, if not nil.
func (c *cdpClient) call(method string, params map[string]any, result any) error {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan cdpResponse, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	_, err = c.w.Write(append(data, 0))
	c.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", method, resp.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	case <-c.done:
		return errBrowserClosed
	case <-time.After(callTimeout):
		return fmt.Errorf("%s: the browser did not answer within %s", method, callTimeout)
	}
}
