package com.makina.security.OpenPLAIDSAM;

import javacard.security.*;

public class Config {

	/*
	 * Applet Configuration Parameters
	 */

	// The length of the extended APDU buffer (used for SET DATA only)
	// NOTE:
	// This length allows for the largest size we expect from the SetData command.
	// Estimations:
	//  10 - EXTENDED APDU (CLA|INS|P1|P2|LC0-2|LE0-2)
	// 339 - COMMAND (HEADER|COUNTER|OPERATION|ID|IA MODULUS|IA EXPONENT|FA KEY|8 ACCESS RULES|HASH)
	//  32 - EXTRA HASH (For calculation, need 32 even though we only use 16)	
	// --------------------------------
	// 381 - TOTAL EXTENDED APDU BUFFER
	// 384 - ROUND UP (NEXT MULTIPLE OF 32)
	public static final short LENGTH_COMMAND_BUFFER	= (short)384;
		 
	// The maximum number of keys in the PLAID key container
	public static final short MAX_KEYS_PLAID = (short)8;

	// The length of the AES key in bits
	public static final short LENGTH_AES_KEY_BITS = KeyBuilder.LENGTH_AES_128;

	// The length of the RSA key in bits
	public static final short LENGTH_RSA_KEY_BITS = KeyBuilder.LENGTH_RSA_2048;	

	// The length of the RSA public exponent in bytes
	public static final short LENGTH_RSA_PUBLIC_EXPONENT = (short)3;	
	
	// The type of the RSA private key
	public static final byte TYPE_RSA_PRIVATE = KeyBuilder.TYPE_RSA_CRT_PRIVATE;

	// The number of retries before blocking the operator PIN
	public static final byte PIN_RETRIES_MAX 		= (byte)6;

	// The largest COUNTER value that PLAID will allow before a re-authentication is required
	// NOTE: This is to ensure it fits in a single ASN1 INTEGER byte
	public static final byte MAX_COUNTER 			= (short)127;
	
	// The length of the Electronic Serial Number associated with this instance
	public static final short LENGTH_ESN 			= (short)4;

	// The minimum length of the operator PIN
	public static final byte LENGTH_PIN_MIN 		= (byte)6;

	// The maximum length of the operator PIN
	public static final byte LENGTH_PIN_MAX 		= (byte)6;

	// The length of the encoding profile associated with this instance
	public static final short LENGTH_PROFILE 		= (short)2;

	// The total length of the diversification data (including host+system components)
	public static final short LENGTH_DIV_MAX 		= (short)31;

	// The maximum length permitted for system diversifier (allow for 1 extra length byte)
	public static final short LENGTH_DIV_SYSTEM 	= (short)17; // 16 + 1

	// The maximum length permitted for host diversifier (allow for 1 extra length byte)
	public static final short LENGTH_DIV_HOST 		= (short)16; // 15 + 1	
	
	/*
	 * APPLET FEATURES
	 */

	// !!!!!!! WARNING !!!!!!!
	// This must only be enabled for protocol debugging and analysis, as this forces the applet
	// to use FIXED values for RND1 and DIVDATA according to the ISO 25185-1 Annex A test values.	 
	// !!!!!!! WARNING !!!!!!!	
	public static final boolean FEATURE_PLAID_TEST_VECTORS = false;

	// If enabled, the PACSAM is restricted to the contact (ISO7816) interface only
	public static final boolean FEATURE_RESTRICT_TO_CONTACT = true;

	// If enabled, the command buffer will be stored in RAM instead of EEPROM
	// For higher-RAM platforms
	public static final boolean FEATURE_EXTENDED_APDU_IN_RAM = true;
	 
	// If enabled, will prevent the 'system diversifier' from being returned to the host.
	public static final boolean FEATURE_HIDE_DIV_SYSTEM = true;
	
	// If enabled, transient objects will clear on RESET instead of DESELECT
	public static final boolean FEATURE_CLEAR_ON_RESET = true;
	
	// If enabled, the applet will not permit selection if it is in the TERMINATED state
	// Leave disabled if you wish to interrogate the PACSAM via GET STATUS even when terminated.
	public static final boolean FEATURE_PREVENT_SELECT_IF_TERMINATED = false;
	
	//
	// ISO Test Vectors
	//
	
	// RND2
	public static final byte[] ISO_TEST_RND2 = new byte[] {
		(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, 
		(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02
	};
	
}


