package com.makina.security.OpenPLAIDSAM;

import javacard.framework.Util;

public class UtilEx {
	
	//
	// Helper constants
	//	
	public static final byte ZERO_BYTE		= (byte)0;
	public static final short ZERO_SHORT	= (short)0;
	public static final short LENGTH_BYTE 	= (short)1;
	public static final short LENGTH_SHORT = (short)2;

	public static final short LENGTH_BLOCK_DES 	= (short)8;
	public static final short LENGTH_BLOCK_AES 	= (short)16;
	public static final short LENGTH_KEY_DES 	= (short)16;
	public static final short LENGTH_KEY_AES 	= (short)16;
	public static final short LENGTH_CRC16 		= (short)2;
	public static final short LENGTH_CRC32 		= (short)4;
	public static final short LENGTH_CMAC 		= (short)8;		

	/**
	 * Performs a 3-pass wipe of a data buffer
	 */
	public static void zeroize(byte[] buffer, short offset, short length) {
		
		Util.arrayFillNonAtomic(buffer, offset, length, (byte)0x00);
		Util.arrayFillNonAtomic(buffer, offset, length, (byte)0xFF);
		Util.arrayFillNonAtomic(buffer, offset, length, (byte)0x00);
				
	}

	/**
	 * Rolls a byte array left by 1 bit
	 */
	public static void rollLeft(byte[] buffer, short offset, short length) {
						
		// The carry byte is used to store the carry bit for both the current and previous bytes
		byte carry = 0;
		short end = (short)(offset + length - 1);

		// Traverse backwards through the array
		for (short i = end; i >= offset; i-- )
		{
			// Store the carry bit for this byte
			carry |= (buffer[i] & 0x80);
			
			// Shift this byte by 1
			buffer[i] <<= 1;
			
			// Restore the previous byte's carry bit
			buffer[i] |= (carry & 0x01);
			
			// Unsigned-right-shift this byte's carry bit down to first position
			// NOTE: Due to int promotion of this signed type, we have to mask off
			// 		 to the first byte of the promoted carry value.
			carry = (byte)((carry & 0xFF) >>> 7);
		}
		
		// Apply the final carry bit (it will only ever be 0x01 or 0x00)
		// buffer[end] |= carry;
	}
}
