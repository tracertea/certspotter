module github.com/tracertea/src/certspotter

go 1.24.4

require (
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.15.0
)

require golang.org/x/text v0.26.0 // indirect

retract v0.19.0 // Contains serious bugs.
