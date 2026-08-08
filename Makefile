.PHONY: build test demo demo-gif

build:
	go build -o wardline ./cmd/wardline

test:
	go test ./...

# Run the live auto-block demo in this terminal.
demo: build
	./demo/run.sh

# Re-record the demo GIF (requires charmbracelet/vhs). Writes
# docs/images/wardline-demo.gif.
demo-gif: build
	vhs demo/demo.tape
