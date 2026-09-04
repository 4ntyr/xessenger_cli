package proto

// replayWindow implements the sliding-window replay protection described in
// docs/protocol.md §8. It tracks which sequence numbers in the last
// windowSize values below (and including) the highest have been seen.
//
// Invariants:
//   - sequence numbers are monotonically increasing per direction
//   - a seq > highest always slides the window and is accepted
//   - a seq within (highest-windowSize, highest] is accepted iff unseen
//   - anything older is a replay/too-old and is dropped
const windowSize = 1024

type replayWindow struct {
	highest uint64
	started bool
	bitmap  [windowSize / 64]uint64
}

// check accepts a sequence number if it is fresh; it marks it seen.
func (w *replayWindow) check(seq uint64) bool {
	if !w.started {
		w.started = true
		w.highest = seq
		w.mark(seq)
		return true
	}
	switch {
	case seq > w.highest:
		shift := seq - w.highest
		w.slide(shift)
		w.highest = seq
		w.mark(seq)
		return true
	case seq == w.highest:
		return false // exact duplicate of the most recent
	default: // seq < w.highest
		age := w.highest - seq
		if age >= windowSize {
			return false // too old
		}
		if w.seen(seq) {
			return false // replayed
		}
		w.mark(seq)
		return true
	}
}

// slide shifts the bitmap right by `shift` positions (dropping old bits).
func (w *replayWindow) slide(shift uint64) {
	if shift >= windowSize {
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}
	words := shift / 64
	bits := shift % 64
	// Move from the top down so we don't clobber words we still need.
	for i := len(w.bitmap) - 1; i >= 0; i-- {
		src := i - int(words)
		var v uint64
		if src >= 0 {
			v = w.bitmap[src] << bits
			if bits != 0 && src-1 >= 0 {
				v |= w.bitmap[src-1] >> (64 - bits)
			}
		}
		w.bitmap[i] = v
	}
}

func (w *replayWindow) bitIndex(seq uint64) (word, bit uint64) {
	// bit 0 of word 0 is `highest`; higher ages live at higher indices.
	age := w.highest - seq
	return age / 64, age % 64
}

func (w *replayWindow) mark(seq uint64) {
	word, bit := w.bitIndex(seq)
	w.bitmap[word] |= 1 << bit
}

func (w *replayWindow) seen(seq uint64) bool {
	word, bit := w.bitIndex(seq)
	return w.bitmap[word]&(1<<bit) != 0
}
