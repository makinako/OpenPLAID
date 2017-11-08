package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;

public class Padding {
	
	public static short iso9797M2Add(byte[] buffer, short offset, short length) {
		
		final byte CONST_PAD = (byte)0x80;
		
		// Start at the end of the buffer
		short pos = (short)(length + offset);
		
		// Add the padding constant
		buffer[pos++] = CONST_PAD;
		length++;
		
		// Keep adding zeroes until you get to a block length (an empty block will return 1 block)
		while (length < UtilEx.LENGTH_BLOCK_AES || (length % UtilEx.LENGTH_BLOCK_AES != 0)) {
			buffer[pos++] = (byte)0;
			length++;
		}
		
		return length;
	}
	
	public static short iso9797M2Remove(byte[] buffer, short offset, short length) {

		final byte CONST_PAD = (byte)0x80;

		// Start at the last byte of the buffer
		short pos = (short)(length + offset - 1);
		
		// Remove the trailing zeroes
		while ( (pos != offset) && buffer[pos] == (byte)0x00) { pos--; length--; }
		
		// Test for the padding constant
		if (buffer[pos] != CONST_PAD ) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		length--; // Strip the padding byte		

		return length;
	}
}
