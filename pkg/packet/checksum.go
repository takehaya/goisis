package packet

// fletcherChecksum computes the ISO 8473 (RFC 1008) Fletcher checksum over
// data, where checksumOffset is the index within data of the first of the
// two checksum octets. The two checksum octets in data must be zero when
// computing. For LSPs, data starts at the LSP ID field (PDU offset 12) and
// checksumOffset is 12 (the checksum field at PDU offset 24).
func fletcherChecksum(data []byte, checksumOffset int) uint16 {
	c0, c1 := 0, 0
	for i, b := range data {
		c0 += int(b)
		c1 += c0
		// Reduce periodically so the sums never overflow on huge inputs.
		if i%4096 == 4095 {
			c0 %= 255
			c1 %= 255
		}
	}
	c0 %= 255
	c1 %= 255

	x := ((len(data)-checksumOffset-1)*c0 - c1) % 255
	if x <= 0 {
		x += 255
	}
	y := 510 - c0 - x
	if y > 255 {
		y -= 255
	}
	return uint16(x)<<8 | uint16(y) //nolint:gosec // x and y are in [1,255]
}

// fletcherValid reports whether data, with its checksum octets in place,
// has a valid ISO 8473 Fletcher checksum.
func fletcherValid(data []byte) bool {
	c0, c1 := 0, 0
	for i, b := range data {
		c0 += int(b)
		c1 += c0
		if i%4096 == 4095 {
			c0 %= 255
			c1 %= 255
		}
	}
	return c0%255 == 0 && c1%255 == 0
}
