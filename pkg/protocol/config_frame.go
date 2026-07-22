package protocol

import "encoding/binary"

// Setting is a single CONFIG-frame key/value pair. The wire layout is a
// TLV (type(uint16) + length(uint16) + value) sequence carried in the
// frame payload. Values are length-prefixed so unknown settings can be
// skipped safely by an older peer (forward-compatible negotiation).
type Setting struct {
	ID    SettingID
	Value []byte
}

// ConfigPayload is the parsed body of a CONFIG frame: an ordered list of
// settings negotiated between peers after authentication.
type ConfigPayload struct {
	Settings []Setting
}

// EncodeConfig serializes a ConfigPayload into the binary TLV form used on
// the wire. Each setting is written as: type(2) + len(2) + value(len).
func EncodeConfig(c *ConfigPayload) []byte {
	if c == nil {
		return nil
	}
	size := 0
	for _, s := range c.Settings {
		size += 4 + len(s.Value)
	}
	buf := make([]byte, 0, size)
	for _, s := range c.Settings {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:], uint16(s.ID))
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(s.Value)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, s.Value...)
	}
	return buf
}

// DecodeConfig parses the TLV body of a CONFIG frame. Malformed entries
// (truncated length) are skipped rather than failing the whole payload so a
// hostile or buggy peer cannot force a decode panic — we simply apply the
// settings we could read.
func DecodeConfig(payload []byte) *ConfigPayload {
	c := &ConfigPayload{}
	i := 0
	for i+4 <= len(payload) {
		id := SettingID(binary.BigEndian.Uint16(payload[i:]))
		n := int(binary.BigEndian.Uint16(payload[i+2:]))
		i += 4
		if i+n > len(payload) {
			// Truncated value — stop, keep what we parsed.
			break
		}
		val := make([]byte, n)
		copy(val, payload[i:i+n])
		i += n
		c.Settings = append(c.Settings, Setting{ID: id, Value: val})
	}
	return c
}

// GetUint32 returns the value of a setting as a big-endian uint32. It
// returns ok=false when the setting is absent or shorter than 4 bytes.
func (c *ConfigPayload) GetUint32(id SettingID) (uint32, bool) {
	for _, s := range c.Settings {
		if s.ID == id && len(s.Value) >= 4 {
			return binary.BigEndian.Uint32(s.Value), true
		}
	}
	return 0, false
}

// GetUint8 returns the value of a setting as a single byte. Returns
// ok=false when the setting is absent or empty.
func (c *ConfigPayload) GetUint8(id SettingID) (uint8, bool) {
	for _, s := range c.Settings {
		if s.ID == id && len(s.Value) >= 1 {
			return s.Value[0], true
		}
	}
	return 0, false
}

// WithUint32 returns a copy of c with the given setting set/overwritten.
func (c *ConfigPayload) WithUint32(id SettingID, v uint32) *ConfigPayload {
	out := &ConfigPayload{Settings: append([]Setting(nil), c.Settings...)}
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, v)
	for i, s := range out.Settings {
		if s.ID == id {
			out.Settings[i].Value = val
			return out
		}
	}
	out.Settings = append(out.Settings, Setting{ID: id, Value: val})
	return out
}

// WithUint8 returns a copy of c with the given setting set/overwritten.
func (c *ConfigPayload) WithUint8(id SettingID, v uint8) *ConfigPayload {
	out := &ConfigPayload{Settings: append([]Setting(nil), c.Settings...)}
	for i, s := range out.Settings {
		if s.ID == id {
			out.Settings[i].Value = []byte{v}
			return out
		}
	}
	out.Settings = append(out.Settings, Setting{ID: id, Value: []byte{v}})
	return out
}
