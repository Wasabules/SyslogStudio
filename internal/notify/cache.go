package notify

import (
	"sync"
	"text/template"
)

// maxCachedTemplates bounds the compiled-template cache. The key is the
// template text, so a sink edited repeatedly would otherwise accumulate an
// entry per revision for the life of the process.
const maxCachedTemplates = 64

// ttlCache holds compiled templates, keyed by their source text. Compiling is
// the expensive part and the text rarely changes, but this runs at the full
// message rate, so the cache is what keeps the template engine off the hot
// path.
type ttlCache struct {
	mu    sync.Mutex
	items map[string]*template.Template
	errs  map[string]error
}

func newTTLCache() *ttlCache {
	return &ttlCache{
		items: make(map[string]*template.Template),
		errs:  make(map[string]error),
	}
}

func (c *ttlCache) get(text string) (*template.Template, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if t, ok := c.items[text]; ok {
		return t, nil
	}
	// Failures are cached too. Without that, a broken template re-enters the
	// parser for every message — the case where the cache matters most.
	if err, ok := c.errs[text]; ok {
		return nil, err
	}

	if len(c.items)+len(c.errs) >= maxCachedTemplates {
		clear(c.items)
		clear(c.errs)
	}

	t, err := template.New("sink").Parse(text)
	if err != nil {
		c.errs[text] = err
		return nil, err
	}
	c.items[text] = t
	return t, nil
}
