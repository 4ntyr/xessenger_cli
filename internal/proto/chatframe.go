package proto

// SealChat seals a text chat message into a frame.
func (s *Session) SealChat(text string) ([]byte, error) {
	return s.Seal(TypeChat, encodeChatPayload(text))
}

// DecodeChat decodes an already-opened chat plaintext into its text.
func DecodeChat(plaintext []byte) (string, error) { return decodeChatPayload(plaintext) }
