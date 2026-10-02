package web

import _ "embed"

// Index is the embedded console shell. The server remains a single binary.
//
//go:embed index.html
var Index []byte

// IconSquare is the Keel brand mark used by the embedded console shell.
// It is served from the same binary so the console has no external asset
// dependency.
//go:embed keel-icon-square.svg
var IconSquare []byte
