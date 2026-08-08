package adapter

// rawCodecName is the encoding name registered for the passthrough codec.
// It is deliberately not "proto": forcing this codec on both the server and
// the upstream client makes Wardline relay message bytes verbatim, so it
// never needs any relayed service's generated protobuf types.
const rawCodecName = "wardline-raw-proxy"

// rawFrame is one opaque gRPC message. The proxy carries the raw wire bytes
// through untouched -- it never decodes a message, so it can forward any
// method of any service without that service's proto schema.
type rawFrame struct {
	payload []byte
}

// rawCodec is a gRPC encoding.Codec that does no encoding: Marshal returns
// the frame's bytes and Unmarshal copies bytes into a frame. Registering it
// as the forced server + client codec turns the whole gRPC server into a
// transport-agnostic byte relay.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	return v.(*rawFrame).payload, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	f := v.(*rawFrame)
	// Copy: gRPC reuses the read buffer after Unmarshal returns, so holding
	// data directly would let a later read corrupt an in-flight frame.
	f.payload = append(f.payload[:0], data...)
	return nil
}

func (rawCodec) Name() string { return rawCodecName }
