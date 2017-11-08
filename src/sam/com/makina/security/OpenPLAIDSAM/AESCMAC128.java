package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;
import javacard.security.*;

/**
 * Signature algorithm ALG_AES_CMAC_128 generates a 16-byte Cipher-based MAC (CMAC) 
 * using AES with blocksize 128 in CBC mode with ISO9797_M2 padding scheme.
 */
public class AESCMAC128 extends Signature  {

	// Algorithm constant (Matches the Javacard 3.x value)
	public static final byte ALG_AES_CMAC_128 	= (byte)49;

	// Cryptographic Service Providers
	private Signature cspAESMAC;

	private static final short ZERO 			= (short)0;
	public static final short LENGTH_BLOCK_AES 	= (short)16;
	public static final short LENGTH_KEY_AES 	= (short)16;
	public static final short LENGTH_CMAC 		= (short)16; // We return the entire CMAC 

	// Constant XOR value according to AES-CMAC-128 for subkey generation
	private static final byte CONST_RB 			= (byte)0x87;		
	private static final byte CONST_PAD 		= (byte)0x80;

	// A temporary working space
	private byte[] buffer;
	
	private static final short LENGTH_BUFFER 	= (short)48;

	// Holds L, K1 and K2 during processing
	private static final short OFFSET_SUBKEY	= (short)0;
	private static final short LENGTH_SUBKEY	= LENGTH_BLOCK_AES;

	// Holds the intermediate values as well as the final CMAC
	private static final short OFFSET_CMAC 		= (short)(OFFSET_SUBKEY + LENGTH_SUBKEY);
	
	public AESCMAC128() {		
		
		// Create the cryptographic service providers
		cspAESMAC = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);		
		buffer = JCSystem.makeTransientByteArray(LENGTH_BUFFER, JCSystem.CLEAR_ON_RESET);
	}
	
	public byte getAlgorithm() {
		return ALG_AES_CMAC_128;
	}
	
	public short getLength() {
		return LENGTH_CMAC;
	}
	
	public void init(Key theKey, byte theMode)  {
		init(theKey, theMode, null, ZERO, ZERO);
	}

	public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen)  {

		// Reset our entire buffer
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);

		/*
		 * SUBKEY GENERATION
		 */
		 
		// Step 1.  L := AES-128(K, const_Zero);  
		// In step 1, AES-128 with key K is applied to an all-zero input block.
		// NOTE: The IV is always zero for this step as it is not the actual CMAC calculation
		cspAESMAC.init(theKey, Signature.MODE_SIGN);
		cspAESMAC.sign(buffer, OFFSET_SUBKEY, LENGTH_BLOCK_AES, buffer, OFFSET_SUBKEY);		
		
		// buffer[OFFSET_SUBKEY] now contains the value of L, this is the only portion of the Subkey generation
		// we perform here, as the rest is in the sign() or verify() method when we know the length of the
		// final block.
		
		// Now we initialise cspAES with theKey and our IV (if supplied), for the actual CMAC operation
		if (bArray != null) {
			cspAESMAC.init(theKey, theMode, bArray, bOff, bLen);
		} else {
			cspAESMAC.init(theKey, theMode);			
		}		
	}
	
	public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)  {

		/*
		 * First, call update() until we have <= LENGTH_BLOCK_AES bytes to process (which may be zero times)
		 * This ensures we are dealing only with the last block and also handles the case where
		 * inLength == 0.
		 */
		while (inLength > LENGTH_BLOCK_AES) {
						
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
						
		}
		
		// We now know that we are dealing with the last block
		processFinalBlock(inBuff, inOffset, inLength);

		// We now know that buffer[OFFSET_CMAC] contains the final block to process

		// Perform the final CBC encipherment on the last block, writing it back to the same location
		cspAESMAC.sign(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, buffer, OFFSET_CMAC);
		
		// buffer[OFFSET_CMAC] now contains the CMAC (untrimmed)
		
		// Write the trimmed CMAC value to the outBuffer
		Util.arrayCopyNonAtomic(buffer, OFFSET_CMAC, sigBuff, sigOffset, LENGTH_CMAC);

		// Reset our internal buffer
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);
		
		// Return the length of the CMAC
		return LENGTH_CMAC;
	}

	public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) {

		/*
		 * We allow the applet to compare the first 1 < sigLength < LENGTH_CMAC bytes
		 * because it is common to truncate the result of a CMAC and this is certainly
		 * true of the DESFire, where it uses the first 8 bytes
		 */

		// Is the supplied length less than 1 or greater than a full CMAC? If not, instant fail
		if (sigLength <= 0 || sigLength > LENGTH_CMAC) return false;

		/*
		 * First, call update() until we have <= LENGTH_BLOCK_AES bytes to process (which may be zero times)
		 * This ensures we are dealing only with the last block and also handles the case where
		 * inLength == 0.
		 */
		while (inLength > LENGTH_BLOCK_AES) {
						
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
						
		}
		
		// We now know that we are dealing with the last block
		processFinalBlock(inBuff, inOffset, inLength);

		// We now know that buffer[OFFSET_CMAC] contains the final block to process

		// Perform the final CBC encipherment on the last block, writing it back to the same location
		boolean result = cspAESMAC.verify(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, sigBuff, sigOffset, sigLength);

		// Reset our internal buffer
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);

		// Compare the result against the supplied signature
		return result;
	}

	public void update(byte[] inBuff, short inOffset, short inLength) {
		
		// This is an intermediate operation, so the length must be a multiple of the block size and non-zero
		if (inLength == 0 || (inLength % LENGTH_BLOCK_AES != 0)) {
			CryptoException.throwIt(CryptoException.ILLEGAL_USE);
		}
		
		// We now know that this is a multiple of the block length;
		while (inLength != 0) {
						
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
			
		}
	}
                        	
	/*
	 * Private helper methods
	 */


	/**
	 * This method performs the steps associated with the final message block, including
	 * the generation of subkeys, message length checking, padding and final subkey XOR'ing
	 */
	private void processFinalBlock(byte[] inBuff, short inOffset, short inLength) {

		// In step 2, the number of blocks, n, is calculated.  
		// The number of blocks is the smallest integer value greater than or equal to the quotient 
		// determined by dividing the length parameter by the block length, 16 octets.		
		// NOTE: Not necessary as we know we're in the final block
		
		// In step 3, the length of the input message is checked.  
		// If the input length is 0 (null), the number of blocks to be processed shall be 1, and 
		// 	the flag shall be marked as not-complete-block (false).	
		// Otherwise, if the last block length is 128 bits, the flag is marked as complete-block 
		// 	(true); else mark the flag as not-complete-block (false).
		if (inLength == LENGTH_BLOCK_AES) {			
			
			// We process this as a complete block

			// In step 4, M_last is calculated by exclusive-OR'ing M_n and one of the previously calculated subkeys.  
			// If the last block is a complete block (true), then M_last is the exclusive-OR of M_n and K1.

			// Generate K1
			generateSubkey(buffer, OFFSET_SUBKEY);
			
			for (short i = 0; i < LENGTH_BLOCK_AES; i++) {
				buffer[(short)(OFFSET_CMAC + i)] = (byte)(inBuff[(short)(inOffset + i)] ^ buffer[(short)(OFFSET_SUBKEY + i)]);
			}			
			
			// buffer[OFFSET_CMAC] now contains the XOR of M_last and K1
			
			
		} else {

			// We process this as a not-complete-block

			// In step 4, M_last is calculated by exclusive-OR'ing M_n and one of the previously calculated subkeys.  
			// If the last block is a complete block (true), then M_last is the exclusive-OR of M_n and K1.
			// Otherwise, M_last is the exclusive-OR of padding(M_n) and K2.

			// Handle the special case (from step 3) where the input length is zero
			if (inLength == 0) {
				// Fill the CMAC buffer with zeroes
				Util.arrayFillNonAtomic(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, (byte)0x00);
				
				// Set the first byte to the padding constant
				buffer[OFFSET_CMAC] = CONST_PAD;				
			} else {
				
				// Copy the input buffer to our CMAC buffer
				Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, OFFSET_CMAC, inLength);
				
				// Set the next byte to the padding constant and increment the length to cover it
				buffer[(short)(OFFSET_CMAC + inLength++)] = CONST_PAD;
				
				while (inLength != LENGTH_BLOCK_AES) {
					// Set the next byte to the zero and increment the length to cover it
					buffer[(short)(OFFSET_CMAC + inLength++)] = 0x00;
				}
			}

			// Generate K2 (just execute the Subkey routine twice)
			generateSubkey(buffer, OFFSET_SUBKEY);
			generateSubkey(buffer, OFFSET_SUBKEY);			
			for (short i = 0; i < LENGTH_BLOCK_AES; i++) {
				buffer[(short)(OFFSET_CMAC + i)] ^= buffer[(short)(OFFSET_SUBKEY + i)];
			}			
			
			// buffer[OFFSET_CMAC] now contains the XOR of padding(M_last) and K2
		}		
	}
	
	
	// This method will generate subkey K1 and return it to the same byte array
	// Calling it twice will generate K2
	private void generateSubkey(byte[] l, short offset) {				
		// Step 1 has already been performed in the init() routine
	
		// In step 2, K1 is derived through the following operation:
		
		// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
		if ((l[offset] & 0x80) == 0x00) {
			UtilEx.rollLeft(buffer, offset, LENGTH_BLOCK_AES);
		}			
		// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.		
		else {
			UtilEx.rollLeft(l, offset, LENGTH_BLOCK_AES);
			l[(short)(offset + LENGTH_BLOCK_AES - 1)] ^= CONST_RB;				
		}

		// In step 3, K2 is derived through the following operation:							
		// If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
		// Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

		// NOTE: This is just the same operation as for K1, but twice. So call it twice!
	}
	
	/*
	public static void Test() {

		// Tests this implementation according to https://tools.ietf.org/html/rfc4493#section-2.4
		
		Signature sig = new AESCMAC128();
		
		byte[] k = new byte[] { 
			(byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6, 
			(byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88, (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
		}; // Length 16 bytes
		
		byte[] d1 = new byte[0];
		// Expect bb1d6929 e9593728 7fa37d12 9b756746
		
		byte[] d2 = new byte[] { 
			(byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96, 
			(byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A
		}; // Length 16 bytes
		// Expect 070a16b4 6b4d4144 f79bdd9d d04a287c
		
		byte[] d3 = new byte[] { 
			(byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96, 
			(byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A, 
			(byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57, (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C, 
			(byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC, (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51, 
			(byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46, (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11
		 }; // Length 40 bytes
		// Expect dfa66747 de9ae630 30ca3261 1497c827
		
		byte[] d4 = new byte[] { 
			(byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96, 
			(byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A, 
			(byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57, (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C, 
			(byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC, (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51, 
			(byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46, (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11, 
			(byte)0xE5, (byte)0xFB, (byte)0xC1, (byte)0x19, (byte)0x1A, (byte)0x0A, (byte)0x52, (byte)0xEF, 
			(byte)0xF6, (byte)0x9F, (byte)0x24, (byte)0x45, (byte)0xDF, (byte)0x4F, (byte)0x9B, (byte)0x17, 
			(byte)0xAD, (byte)0x2B, (byte)0x41, (byte)0x7B, (byte)0xE6, (byte)0x6C, (byte)0x37, (byte)0x10
		 }; // Length 64 bytes 
		// Expect 51f0bebf 7e3b9d92 fc497417 79363cfe
 
		byte[] m = new byte[16];
		boolean ok = false;
		
		AESKey key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		key.setKey(k, ZERO);
		
		sig.init(key, Signature.MODE_SIGN);
		sig.sign(d1, ZERO, (short)d1.length, m, ZERO);		
		
		sig.init(key, Signature.MODE_VERIFY);
		ok = sig.verify(d1, ZERO, (short)d1.length, m, ZERO, (short)16);		

		sig.init(key, Signature.MODE_SIGN);
		sig.sign(d2, ZERO, (short)d2.length, m, ZERO);
		
		sig.init(key, Signature.MODE_VERIFY);
		ok = sig.verify(d2, ZERO, (short)d2.length, m, ZERO, (short)16);		
		
		sig.init(key, Signature.MODE_SIGN);
		sig.sign(d3, ZERO, (short)d3.length, m, ZERO);
		
		sig.init(key, Signature.MODE_VERIFY);
		ok = sig.verify(d3, ZERO, (short)d3.length, m, ZERO, (short)16);		
		
		sig.init(key, Signature.MODE_SIGN);
		sig.sign(d4, ZERO, (short)d4.length, m, ZERO);

		sig.init(key, Signature.MODE_VERIFY);
		ok = sig.verify(d4, ZERO, (short)d4.length, m, ZERO, (short)16);		
		
		
	}
	*/
}
