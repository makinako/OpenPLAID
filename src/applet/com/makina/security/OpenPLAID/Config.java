package com.makina.security.OpenPLAID;

import javacard.security.*;

public class Config {

	/*
	 * APPLET CONFIGURATION PARAMETERS
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
	// 384 - ROUND UP (NEXT MULTIPLE OF 32 FOR EEPROM ALLOCATION)
	public static final short LENGTH_COMMAND_BUFFER	= (short)384;

	// The length of the RSA Initial Authenticate key in bits
	// NOTE: Changing this value is not tested in this release!
	public static final short LENGTH_IA_KEY_BITS 	= KeyBuilder.LENGTH_RSA_2048;	
	public static final short LENGTH_IA_KEY 		= (short)(LENGTH_IA_KEY_BITS / 8);	

	// The length of the RSA public exponent in bytes
	public static final short LENGTH_IA_EXPONENT 	= (short)3;	
	
	// The length of the AES Final Authenticate key in bits
	// NOTE: Changing this value is not tested in this release!
	public static final short LENGTH_FA_KEY_BITS 	= KeyBuilder.LENGTH_AES_128;
	public static final short LENGTH_FA_KEY 		= (short)(LENGTH_FA_KEY_BITS / 8);

	// The number of Keysets to allocate space for
	// NOTE: This includes the mandatory SHILL and ADMIN keys
	public static final short COUNT_KEYSETS		= (short)5;	
	
	// The number of ACSRecords to allocate space for (including the shill ACSRecord)
	public static final short COUNT_ACSRECORDS 	= (short)6;
	
	// The maximum length of each ACS Record
	public static final short LENGTH_ACSRECORD 	= (short)16;
	
	// The number of Access Rules to allocate space for
	// NOTE: This is the total number for any combination of keyset/acsrecord
	public static final short COUNT_ACCESS_RULES 	= (short)25;

	// The largest COUNTER value that PLAID will allow before a re-authentication is required
	// NOTE: This is to ensure it fits in a single ASN1 INTEGER byte
	public static final byte MAX_COMMAND_COUNTER = (short)127;
	
	/* 
	 * APPLET FEATURES
	 */
	 
	// !!!!!!! WARNING !!!!!!!
	// This must only be enabled for protocol debugging and analysis, as this forces the applet
	// to use FIXED values for RND1 and DIVDATA according to the ISO 25185-1 Annex A test values.	 
	// !!!!!!! WARNING !!!!!!!	
	public static final boolean FEATURE_PLAID_TEST_VECTORS = false;

	// If enabled, the administrative keyset will be restricted to the contact interface
	// NOTE: This also includes personalisation!
	public static final boolean FEATURE_RESTRICT_ADMIN_TO_CONTACT = false;

	// If enabled, the command buffer will be stored in RAM instead of EEPROM
	// For higher-RAM platforms
	public static final boolean FEATURE_EXTENDED_APDU_IN_RAM = true;

	// If enabled, transient objects will clear on RESET instead of DESELECT
	public static final boolean FEATURE_CLEAR_ON_RESET = false;

	// If enabled, administrative (persistant) data changes will be done in a transaction
	public static final boolean FEATURE_USE_TRANSACTIONS = false;

	// If enabled, the administrative keyset can read any ACSRecord regardless of permissions set
	public static final boolean FEATURE_ADMIN_GLOBAL_PERMISSIONS = true;

	// If enabled, a bad finalAuthenticate check will return an error
	// If disabled, a bad finalAuthenticate will produce a SHILL (random) ACSRecord
	public static final boolean FEATURE_FAIL_ON_BAD_AUTH = false;
	
	// If enabled, a good finalAuthenticate with an invalid opMode or bad permission will return an error
	// If disabled, it will continue to produce a SHILL (random) ACSRecord
	public static final boolean FEATURE_FAIL_ON_BAD_OPMODE = false;

	// If enabled, PLAID authentication will strictly enforce the M2 padding scheme requirement.
	// Note that this only affects the Final Authentication component of the PLAID authentication
	// as the personalisation scheme will always enforce strict M2 padding.
	public static final boolean FEATURE_STRICT_ISO9797_M2_PADDING = true;

	// If enabled, the PLAID applet will automatically progress to the STATE_PERSONALISED lifecycle
	// state when the administrative key is changed. This allows the possibility of a card issuer to
	// fully personalise a card without having the administrative private key part.
	public static final boolean FEATURE_ACTIVATE_ON_ADMIN_KEY_CHANGE = true;

	/*
	 * DEFAULT KEY INFORMATION
	 */

	// The identifer for the Administrative keyset
	public static final short KEYSET_ADMIN		= (short)0;
		
	// The identifer for the Shill (dummy) keyset
	public static final short KEYSET_SHILL		= (short)-1;

	//
	// KEY_TRANSPORT_IA
	// This is the modulus for the transport key. It is used for the initial transportation
	// of personalisation data and is assigned to the ADMIN keyset.
	//
	// NOTE: This could just as easily be injected via GP install parameters
	//
	public static final byte[] KEY_TRANSPORT_IA_MODULUS = new byte[] { 
		(byte)0xD4, (byte)0xA3, (byte)0xC0, (byte)0xC8, (byte)0x56, (byte)0x7A, (byte)0xEF, (byte)0x46, 
		(byte)0x36, (byte)0x18, (byte)0x8B, (byte)0x61, (byte)0x02, (byte)0xFF, (byte)0x5F, (byte)0xFA, 
		(byte)0xF6, (byte)0xAB, (byte)0x87, (byte)0x04, (byte)0xCF, (byte)0x52, (byte)0x38, (byte)0x45, 
		(byte)0x1B, (byte)0x6A, (byte)0x68, (byte)0xD9, (byte)0xEE, (byte)0x63, (byte)0x4E, (byte)0xAE, 
		(byte)0x76, (byte)0xA6, (byte)0xEF, (byte)0xB4, (byte)0x31, (byte)0xEE, (byte)0x10, (byte)0xA1, 
		(byte)0x21, (byte)0xA6, (byte)0xFD, (byte)0x9D, (byte)0xBC, (byte)0x0B, (byte)0xCE, (byte)0x34, 
		(byte)0x2D, (byte)0xC7, (byte)0x7A, (byte)0x84, (byte)0x29, (byte)0x1D, (byte)0x63, (byte)0x76, 
		(byte)0x07, (byte)0x68, (byte)0xB8, (byte)0x6C, (byte)0x64, (byte)0xCB, (byte)0xAC, (byte)0x1D, 
		(byte)0x9C, (byte)0x18, (byte)0xC0, (byte)0x61, (byte)0xF4, (byte)0x45, (byte)0xDB, (byte)0xB5, 
		(byte)0x15, (byte)0x54, (byte)0xC2, (byte)0xB1, (byte)0x87, (byte)0x33, (byte)0x3A, (byte)0x7E, 
		(byte)0xF6, (byte)0x71, (byte)0x9B, (byte)0x3C, (byte)0xEC, (byte)0xEC, (byte)0x11, (byte)0x5D, 
		(byte)0x6F, (byte)0x77, (byte)0xA9, (byte)0x8D, (byte)0x3B, (byte)0x8D, (byte)0x74, (byte)0x4F, 
		(byte)0xF2, (byte)0x26, (byte)0x4B, (byte)0x47, (byte)0x6A, (byte)0xE8, (byte)0xD3, (byte)0x57, 
		(byte)0xC9, (byte)0xD5, (byte)0x2B, (byte)0x73, (byte)0x49, (byte)0x33, (byte)0x85, (byte)0x15, 
		(byte)0x28, (byte)0xD5, (byte)0xC9, (byte)0x4A, (byte)0x77, (byte)0x77, (byte)0xF0, (byte)0xA0, 
		(byte)0xAF, (byte)0xFA, (byte)0xAA, (byte)0x25, (byte)0xA4, (byte)0x30, (byte)0x71, (byte)0x00, 
		(byte)0xD4, (byte)0x77, (byte)0x2A, (byte)0xA0, (byte)0x64, (byte)0x96, (byte)0x10, (byte)0x6E, 
		(byte)0xA8, (byte)0x59, (byte)0xD0, (byte)0x08, (byte)0x49, (byte)0x74, (byte)0xB7, (byte)0xA9, 
		(byte)0x97, (byte)0x24, (byte)0x59, (byte)0xFD, (byte)0x78, (byte)0x66, (byte)0xB7, (byte)0x51, 
		(byte)0x56, (byte)0xEF, (byte)0x1E, (byte)0xA1, (byte)0xD2, (byte)0xF6, (byte)0xBE, (byte)0xCB, 
		(byte)0x2F, (byte)0x4B, (byte)0x21, (byte)0xDE, (byte)0x42, (byte)0x27, (byte)0xD0, (byte)0x1E, 
		(byte)0xF7, (byte)0x6C, (byte)0xF1, (byte)0xB2, (byte)0x2A, (byte)0x20, (byte)0x96, (byte)0xF1, 
		(byte)0x21, (byte)0x81, (byte)0xDD, (byte)0x0C, (byte)0xAD, (byte)0x9D, (byte)0xCE, (byte)0x72, 
		(byte)0xCA, (byte)0xBD, (byte)0xEA, (byte)0xE4, (byte)0x20, (byte)0xBD, (byte)0xCE, (byte)0x21, 
		(byte)0x98, (byte)0x8F, (byte)0x2A, (byte)0x0D, (byte)0x68, (byte)0x34, (byte)0xA1, (byte)0x30, 
		(byte)0x58, (byte)0x7F, (byte)0xA9, (byte)0x11, (byte)0xF5, (byte)0x3E, (byte)0x37, (byte)0x78, 
		(byte)0x34, (byte)0x6C, (byte)0xD0, (byte)0xAD, (byte)0xB7, (byte)0xB4, (byte)0x05, (byte)0xDF, 
		(byte)0x71, (byte)0x42, (byte)0x13, (byte)0xB6, (byte)0x4C, (byte)0xD9, (byte)0xBE, (byte)0x75, 
		(byte)0x13, (byte)0xBC, (byte)0xD3, (byte)0x27, (byte)0xB4, (byte)0xD9, (byte)0x60, (byte)0x3E, 
		(byte)0x04, (byte)0x82, (byte)0x0C, (byte)0x8B, (byte)0xF7, (byte)0xE3, (byte)0xD2, (byte)0x8E, 
		(byte)0xE4, (byte)0xAF, (byte)0x4F, (byte)0x7B, (byte)0x4E, (byte)0x99, (byte)0x44, (byte)0xF0, 
		(byte)0xEC, (byte)0x6E, (byte)0x8E, (byte)0x27, (byte)0x67, (byte)0x02, (byte)0x97, (byte)0x29
	 }; // Length 256 bytes

 	// The public exponent value (also used for the SHILL key) uses the common value 65537.
	public static final byte[] KEY_TRANSPORT_IA_EXPONENT = { (byte)0x01, (byte)0x00, (byte)0x01 };
 
	public static final byte[] ISO_TEST_DIVDATA = new byte[] {
		(byte)0x0B, (byte)0x0B, (byte)0x0B, (byte)0x0B, (byte)0x0B, (byte)0x0B, (byte)0x0B, (byte)0x0B, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	};
	
	public static final byte[] ISO_TEST_RND1 = new byte[] {
		(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, 
		(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01
	};

	public static final byte[] ISO_TEST_FAKEY = new byte[] {
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
	};

}


