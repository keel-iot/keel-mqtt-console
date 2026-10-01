package web

import _ "embed"

// Index is the embedded console shell. The server remains a single binary.
//
//go:embed index.html
var Index []byte
