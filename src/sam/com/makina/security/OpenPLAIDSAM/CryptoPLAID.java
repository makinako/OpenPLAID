package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class CryptoPLAID {

	// Cryptographic Service Providers
	private Cipher cspRSA;
	private Cipher cspAES;
	private MessageDigest cspSHA;	
	private RandomData cspRNG;	

	// Session keys
	private AESKey sessionKey;		// General PLAID session key
	private AESKey transportKey;	// Transport FA key (loaded by a call to loadFAKey)

	// Session state
	private byte[] sessionState;
	

	//
	// CONSTANTS
	// 

	// Helper constants
	private static final byte ZERO_BYTE		= (byte)0;
	private static final short ZERO_SHORT	= (short)0;
	private static final short LENGTH_BYTE 	= (short)1;
	private static final short LENGTH_SHORT = (short)2;
		
	// PLAID authentication state enumerations
	public static final byte AUTH_STATE_NONE 	= (byte)0;
	public static final byte AUTH_STATE_IAKEY 	= (byte)1;
	public static final byte AUTH_STATE_OK 		= (byte)2;	

	private static final short LENGTH_BLOCK_AES = (short)(Config.LENGTH_AES_KEY_BITS / 8);
	private static final short LENGTH_KEY_AES 	= (short)(Config.LENGTH_AES_KEY_BITS / 8);

	private static final short LENGTH_BLOCK_RSA = (short)(Config.LENGTH_RSA_KEY_BITS / 8);
	private static final short LENGTH_KEY_RSA 	= (short)(Config.LENGTH_RSA_KEY_BITS / 8);

	//
	// PLAID protocol constants
	// 
	private static final short LENGTH_PAYLOAD	= (short)0; // Optional Payloads feature not implemented
	private static final short LENGTH_KEYSET_ID	= (short)2;	
	private static final short LENGTH_OPMODE_ID = (short)2;
	private static final short LENGTH_ACSRECORD	= (short)16;
	private static final short LENGTH_SHA256	= (short)32;
	private static final short LENGTH_KEYSHASH	= LENGTH_KEY_AES;	
	private static final short LENGTH_DIVDATA 	= LENGTH_BLOCK_AES;
	private static final short LENGTH_RND1 		= LENGTH_BLOCK_AES;
	private static final short LENGTH_RND2 		= LENGTH_BLOCK_AES;
	private static final short LENGTH_STR1 		= (short)(LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1 + LENGTH_RND1);
	private static final short LENGTH_STR2 		= (short)(LENGTH_OPMODE_ID + LENGTH_RND2 + LENGTH_PAYLOAD + LENGTH_KEYSHASH);
	private static final short LENGTH_STR3 		= (short)(LENGTH_ACSRECORD + LENGTH_PAYLOAD + LENGTH_DIVDATA);
		
	//
	// PLAID administrative constants (non-ISO)
	//	
	
	// Operations (Also serves as the Parameter tags)
	public static final short OP_ACTIVATE			= (short)1;
	public static final short OP_BLOCK				= (short)2;
	public static final short OP_UNBLOCK			= (short)3;
	public static final short OP_TERMINATE			= (short)4;
	public static final short OP_KEY_CREATE			= (short)5;
	public static final short OP_KEY_DELETE			= (short)6;
	public static final short OP_KEY_DELETE_ALL		= (short)7;
	public static final short OP_ACSR_CREATE		= (short)8;
	public static final short OP_ACSR_DELETE		= (short)9;
	public static final short OP_ACSR_DELETE_ALL	= (short)10;
	//public static final short OP_PAYLOAD_CREATE		= (short)11;
	//public static final short OP_PAYLOAD_DELETE		= (short)12;
	//public static final short OP_PAYLOAD_DELETE_ALL = (short)13;

	// Lengths
	public static final short LENGTH_OP_HASH		= (short)16;
	public static final short LENGTH_GETKEY_HASH	= (short)16;

	// Tags - General
	public static final byte TAG_SAMID = (byte)30;

	// Tags - Keyset
	public static final byte TAG_KEYSET_IAMODULUS = (byte)11;
	public static final byte TAG_KEYSET_IAEXPONENT = (byte)12;
	public static final byte TAG_KEYSET_FAKEY = (byte)13;

	// Tags - Parameters
	// NOTE: Duplicates are ok here because they are unique to each command
	public static final byte TAG_PARAM_ID = (byte)1;
	public static final byte TAG_PARAM_KEY = (byte)2;
	public static final byte TAG_PARAM_DATA = (byte)2;
	public static final byte TAG_PARAM_RULES = (byte)3;

	//
	// Session Variables
	// 
	
	// The PLAID authentication stage
	private static final short OFFSET_AUTH_STATE 	= (short)0;
	
	// The currently authenticated PLAID keyset
	private static final short OFFSET_AUTH_KEYSET	= (short)1;
	
	// If non-zero, the currently authenticated keyset can create SetData cryptograms
	private static final short OFFSET_AUTH_KEK		= (short)3;
	
	// The authentication counter
	private static final short OFFSET_AUTH_COUNTER	= (short)4;
	
	// The DIVDATA field retrieved from the ICC
	private static final short OFFSET_DIVDATA	 	= (short)5;	
	
	// The KEYSHASH value from the ICC, which is used for the session key
	// NOTE: The length allocated for this is LENGTH_SHA256 because the SHA CSP 
	//		 requires the full untruncated length.
	// TODO: Review whether this can be ditched
	private static final short OFFSET_KEYSHASH	 	= (short)(OFFSET_DIVDATA + LENGTH_DIVDATA);

	private static final short LENGTH_STATE 	 	= (short)(	LENGTH_BYTE + 
																LENGTH_KEYSET_ID +
																LENGTH_BYTE +
																LENGTH_BYTE +
																LENGTH_DIVDATA + 
																LENGTH_SHA256);

	public CryptoPLAID() {

		// Create the cryptographic service providers
		cspRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		cspAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cspSHA = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		cspRNG = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		if (Config.FEATURE_CLEAR_ON_RESET) {
			// Create the state buffer		
			sessionState = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_RESET);

			// Create the session keys
			sessionKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, Config.LENGTH_AES_KEY_BITS, false);
			transportKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, Config.LENGTH_AES_KEY_BITS, false);
		} else {
			// Create the state buffer		
			sessionState = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_DESELECT);

			// Create the session keys
			sessionKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, Config.LENGTH_AES_KEY_BITS, false);
			transportKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, Config.LENGTH_AES_KEY_BITS, false);
		}
	}
	
	public void resetAuthentication() {

		// Reset the session key
		sessionKey.clearKey();
		
		// NOTE: This will implicitly set the AUTH_STATE to STATE_NONE (which must always be 0)
		Util.arrayFillNonAtomic(sessionState, (short)0, LENGTH_STATE, (byte)0);		
		
	}
	
	public boolean getAuthKEK() {
		return (sessionState[OFFSET_AUTH_KEK] != 0);
	}
	
	public byte getAuthState() {
		return sessionState[OFFSET_AUTH_STATE];
	}

	public short getAuthKeyset() {
		return Util.getShort(sessionState, OFFSET_AUTH_KEYSET);
	}

	public short initialAuthenticate(KeyRecord key, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
		
        // Clear any existing authentication state
		resetAuthentication();

		// Check that we have been given the correct key type
		if (key.value.getType() != PLAIDKey.TYPE_PLAID) {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}

		// Check whether this key is permitted to perform an authentication
		if (!key.getAttrPlaidAuth()) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}

		//
		// NOTE: 
		// The expected incoming buffer is:
		// [OPMODE] || [eSTR1]
		//
		
		// Just store and skip the OpMode for now. We'll use it later in the construction of STR2
		short opModeId = Util.getShort(inBuffer, inOffset);
		inOffset += LENGTH_OPMODE_ID; // Move to the start of STR1
		inLength -= LENGTH_OPMODE_ID;

		/*
		 * Response Evaluation (From ISO 25185-1 6.4)
		 */

		// Provide a strong reference to our PLAID keyset
		PLAIDKey plaidKey = (PLAIDKey)key.value;

		// a) The IFD receives string eSTR1 and calculates STR1 where STR1 = RSADecryptIAKey 
		//	  (eSTR1) using the KeySetID values identified in the list.
		try {			
			cspRSA.init(plaidKey.iaKeyPrivate, Cipher.MODE_DECRYPT);
			cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
		} catch (CryptoException ex) {
			// The most likely reason for this exception is that the key was wrong
			// and so the padding validation failed post-decryption.
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		// b) The IFD compares the two copies of RND1 for each value to confirm that 
		//    decryption was successful.
		if (0 != Util.arrayCompare(	outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA),
									outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1),
									LENGTH_RND1)) {
								ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
							  }

		// c) The IFD should traverse the entire list of KeySetID values irrespective of when 
		//    the first successful decryption is performed and store the successful KeySetID 
		//    values. This serves to prevent potential timing attacks.
		//
		// d) Authentication fails if all KeySetID values have been used and decryption fails. 
		// 	  Note that the same Asymmetric keys might be used in multiple key sets for large 
		//    implementations.

		// IMPLEMENTATION NOTE:
		// PACSAM doesn't currently need to be concerned with timing attacks, since it is only
		// used during the personalisation stage. We only test the keyset supplied by the host

		// e) The IFD extracts the ICC diversification seed data DivData and KeySetID value 
		//    from the first successful STR1 decryption.

		// Keyset Id
		short keysetId = Util.getShort(outBuffer, outOffset);

		// Record which Keyset Id we are authenticating with, as well as whether it can act as a KEK
		Util.arrayCopyNonAtomic(outBuffer, outOffset, sessionState, OFFSET_AUTH_KEYSET, LENGTH_KEYSET_ID);
		if (key.getAttrPlaidKEK()) {
			sessionState[OFFSET_AUTH_KEK] = (byte)0x01;
		}

		// DivData
		Util.arrayCopyNonAtomic(outBuffer, (short)(outOffset + LENGTH_KEYSET_ID), sessionState, OFFSET_DIVDATA, LENGTH_DIVDATA);		

		/*
		 * Command processing (From ISO 25185-1 6.5)
		 */
		
		// a) The IFD generates a random value (RND2) using a RNG. The size of RND2 is identical 
		//	  to the key size of the selected AES-128 cipher (16 bytes).
		// NOTE: 
		// - We generate this into the second RND1 value
		cspRNG.generateData(outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1), LENGTH_RND2);		

		/*
		 * TEST VECTOR - RND2
		 * Uncomment the following lines to apply the ISO-25185-1 ISO test vectors as per
		 * http://standards.iso.org/iso/25185/-1/ISO_IEC_25185-1_Annex%20A_TestVectors.rtf		 
		 *
		 * WARNING: THE FOLLOWING IS ONLY TO BE USED DURING PROTOCOL TESTING AND MUST BE
		 * DISABLED IN ALL OTHER CASES !!		 
		 */
		 
		// >> START TEST VECTOR
		if (Config.FEATURE_PLAID_TEST_VECTORS) {		
			Util.arrayCopyNonAtomic(Config.ISO_TEST_RND2, ZERO_SHORT, outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1), LENGTH_RND2);		
		}
		// << END TEST VECTOR

		
		// b) The IFD calculates SHA-256 [RND1||RND2]; the result is denoted as KeysHash.
		cspSHA.reset();
		cspSHA.doFinal(outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA), (short)(LENGTH_RND1 + LENGTH_RND2),
					   sessionState, OFFSET_KEYSHASH);

		// c) The IFD uses the diversification data (DivData) and calculates the diversified final 
		//	  authenticate key where FAKey(Div) = AESEncryptFAKey (DivData). The FAKey to be used is 
		//    referenced by the KeySetID identified as successful in the earlier IA Response evaluation.

		//
		// IMPLEMENTATION NOTE:
		// If a previous call to loadFAKey has been made, we will have a decrypted transport FA Key that
		// we can use for our initial authentication to a non-personalised PLAID applet.		
		if (transportKey.isInitialized()) {						
			// Only permit this if the authenticating keyset has the PLAID_KEK attribute			
			if (!key.getAttrPlaidKEK()) {
				transportKey.clearKey(); // Clear the loaded transport key
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			// There is no need to diversify this key as it is implicitly ICC-unique
			cspAES.init(transportKey, Cipher.MODE_ENCRYPT);			
		} else {
			// This is not a transport authentication, load the normal FA Key and diversify
			cspAES.init(plaidKey.faKey, Cipher.MODE_ENCRYPT);			
		}

		// Generate FAKey(Div)
		cspAES.doFinal(sessionState, OFFSET_DIVDATA, LENGTH_DIVDATA, outBuffer, outOffset);
		transportKey.clearKey(); // Clear the key immediately so it will be ignored on subsequent calls						

		// NOTE: We temporarily use the sessionKey to store the intermediate FAKey(Div) result
		sessionKey.setKey(outBuffer, outOffset); // This will be overwritten shortly
		cspAES.init(sessionKey, Cipher.MODE_ENCRYPT);
		

		// d) The IFD creates the bit string STR2: OpModeID || RND2 || <Payload> || KeysHash
		short offset = outOffset; // Store the outOffset
		
		// OpModeId
		Util.setShort(outBuffer, outOffset, opModeId);
		offset += LENGTH_OPMODE_ID;

		// RND2
		Util.arrayCopyNonAtomic(outBuffer, (short)(outOffset + LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1), 
								outBuffer, offset, 
								LENGTH_RND2);
		offset += LENGTH_RND2;
		
		// <PayLoad>
		// NOTE: Optional Payload not implemented
		offset += LENGTH_PAYLOAD;
		
		// KeysHash
		Util.arrayCopyNonAtomic(sessionState, OFFSET_KEYSHASH, outBuffer, offset, LENGTH_KEYSHASH);
		
		// e) If needed, padding shall consist of one mandatory byte set to 0x80 followed, if required, 
		//	  by 0 to k–1 bytes set to 0x00, until the respective data block is filled up to k bytes, 
		//	  complying with ISO/IEC 9797-1 padding method 2.
		// NOTE: ISO9797-1 Padding Method 2 requires the 0x80 to be written, regardless of whether
		// 	     the input data is block-aligned or not, so we ignore the 'if needed' statement above.		
		//outBuffer[offset++] = (byte)0x80;		
		//offset -= outOffset; // Remove the initial outOffset to leave the length
		//while ( (offset % LENGTH_BLOCK_AES) != ZERO_SHORT ) outBuffer[offset++] = ZERO_BYTE;
		short length = Padding.iso9797M2Add(outBuffer, outOffset, LENGTH_STR2);

		// f) The IFD calculates eSTR2 where eSTR2 = AESEncryptFAKey(Div) (STR2). The cipher mode for 
		//	  this operation is CBC.
		cspAES.doFinal(outBuffer, outOffset, length, outBuffer, outOffset);
		
		// Clear the session key now that the intermediate DivKey is no longer required
		sessionKey.clearKey();
		
		// Set our internal authentication state to AUTH_STATE_IAKEY
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_IAKEY;
		
		// g) The IFD transmits the Final Authenticate string eSTR2 to the ICC			
		return length;
	}
	
	public short finalAuthenticate(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
	
		// Temporarily reset our authentication state, so any error makes us start again
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;

		// Load our session key
		sessionKey.setKey(sessionState, OFFSET_KEYSHASH);		
		cspAES.init(sessionKey, Cipher.MODE_DECRYPT);

		/*
		 * Response Evaluation (From ISO 25185-1 6.8)
		 */
		
		// a) The IFD calculates STR3 where STR3 = AESDecryptKeysHash (eSTR3).
						
		// The input is block-length so we can write back in itself
		cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset); 
		
		// b) The IFD compares the transmitted DivData with the IFD copy received in the IA Response. 
		//	  Authentication fails if they do not match.
		if (0 != Util.arrayCompare(sessionState, OFFSET_DIVDATA, 
								   outBuffer, (short)(outOffset + LENGTH_ACSRECORD + LENGTH_PAYLOAD), 
								   LENGTH_DIVDATA))
		{
			// Clear the authentication state
			resetAuthentication();
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		// c) The ACSRecord and Payload is extracted from STR3 and can now be considered to be authenticated.			
				
		// d) The optional payload may now be processed as required by the implementation rules.		
		// NOTE: Optional Payload functionality not implemented

		// Done! Set our new authentication state
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_OK;
		
		// Return the length of the ACSRecord (Which is already at the start of our buffer)
		return LENGTH_ACSRECORD;
	}
	
	public short setData(KeyRecord[] keys, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

		// Ensure that we are authenticated with KEYSET_ADMIN
		if (getAuthState() != AUTH_STATE_OK) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		// Make sure the currently authenticated keyset has PLAID_KEK attribute
		if (!getAuthKEK()) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

		//
		// Validate and populate the common fields
		//
		
		short offset = inOffset;
		
		// HEADER (SEQUENCE tag)
		offset = TlvReader.find(inBuffer, offset, TlvReader.ASN1_SEQUENCE);
		if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		// COUNTER (INTEGER (1..127) - Should always occupy 1 byte)
		offset = TlvReader.find(outBuffer, offset, TlvReader.ASN1_INTEGER);
		if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		if (TlvReader.getLength(outBuffer, offset) != 1) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

		// Set the counter value
		outBuffer[TlvReader.getDataOffset(outBuffer, offset)] = sessionState[OFFSET_AUTH_COUNTER];
		
		// OPERATION (ENUMERATED - Should always occupy 1 byte)
		offset = TlvReader.find(outBuffer, offset, TlvReader.ASN1_ENUMERATED);
		if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		if (TlvReader.getLength(outBuffer, offset) != 1) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		byte operation = TlvReader.toByte(outBuffer, offset);
		
		//
		// COMMAND PARAMETERS
		//
		
		// keyCreate
		if (OP_KEY_CREATE == operation) {
			
			// Parameters (CHOICE - Tag is the same as the OP code)
			offset = TlvReader.find(outBuffer, offset, OP_KEY_CREATE);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			
			// ID (OCTET STRING (SIZE (2))
			offset = TlvReader.find(outBuffer, offset, TAG_PARAM_ID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			if (TlvReader.getLength(outBuffer, offset) != LENGTH_KEYSET_ID) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short id = TlvReader.toShort(outBuffer, offset);
			
			//
			// Populate the key values
			//

			// keyCreateParameters (SEQUENCE)
			offset = TlvReader.find(outBuffer, offset, TAG_PARAM_KEY);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// PARAMETER iaModulus (OCTET STRING)
			offset = TlvReader.find(outBuffer, offset, TAG_KEYSET_IAMODULUS);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			if (TlvReader.getLength(outBuffer, offset) != LENGTH_KEY_RSA) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short iaModulusOffset = TlvReader.getDataOffset(outBuffer, offset);

			// PARAMETER iaExponent (OCTET STRING)
			offset = TlvReader.findNext(outBuffer, offset, TAG_KEYSET_IAEXPONENT);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			if (TlvReader.getLength(outBuffer, offset) != Config.LENGTH_RSA_PUBLIC_EXPONENT) 
				ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short iaExponentOffset = TlvReader.getDataOffset(outBuffer, offset);

			
			// PARAMETER faKey (OCTET STRING)		
			offset = TlvReader.findNext(outBuffer, offset, TAG_KEYSET_FAKEY);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			if (TlvReader.getLength(outBuffer, offset) != LENGTH_KEY_AES) 
				ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short faKeyOffset = TlvReader.getDataOffset(outBuffer, offset);			

			// Sam Id
			offset = TlvReader.findNext(outBuffer, offset, TAG_SAMID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			if (TlvReader.getLength(outBuffer, offset) != LENGTH_KEYSET_ID) 
				ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short samId = TlvReader.toShort(outBuffer, offset);			

			// NOTE:
			// The Sam Id isn't necessary to transmit to the ICC, but we leave it here anyway 
			// because it saves us having to update the lengths of the parent constructed tags.

			// Look for the requested keyset id
			PLAIDKey key = null;
			for (short i = 0; i < (short)keys.length; i++) {
				if (keys[i].value.getType() != PLAIDKey.TYPE_PLAID) continue;
				if (!keys[i].value.isInitialized()) continue;
				if (keys[i].getId() == samId) {
					key = (PLAIDKey)keys[i].value;
					break;
				}
			}
			if (key == null) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

			// Write the key elements to their respective offsets
			key.iaKeyPublic.getModulus(outBuffer, iaModulusOffset);
			key.iaKeyPublic.getExponent(outBuffer, iaExponentOffset);
			
			// Diversify the FA key according to ISO25185-1 section 10.
			cspAES.init(key.faKey, Cipher.MODE_ENCRYPT);
			cspAES.doFinal(sessionState, OFFSET_DIVDATA, LENGTH_DIVDATA, outBuffer, faKeyOffset);
		}		

		//
		// GENERATE CRYPTOGRAM
		// 
		
		// Generate the HASH element (write to the end of the inBuffer)
		cspSHA.reset();
		cspSHA.doFinal(inBuffer, inOffset, inLength, inBuffer, (short)(inOffset + inLength));
		inLength += LENGTH_OP_HASH;
		
		// Pad the bytes
		inLength = Padding.iso9797M2Add(inBuffer, inOffset, inLength);

		// Encrypt the entire object
		cspAES.init(sessionKey, Cipher.MODE_ENCRYPT);
		cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
		
		// Increment the command counter (we do this last in case we aborted somewhere earlier)
		sessionState[OFFSET_AUTH_COUNTER]++;
		
		// See if we have exceeded our per-session command counter
		if (sessionState[OFFSET_AUTH_COUNTER] >= Config.MAX_COUNTER) {
			resetAuthentication();		
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		// Return the number of bytes in the cryptogram
		return inLength;
	}
		
	public void loadFAKey(KeyRecord key, byte[] buffer, short offset, short length) {

		// Make sure the requested keyset has the PLAID_KEK attribute
		if (!key.getAttrPlaidKEK()) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
	
		// Validate that the length is an RSA block
		if (length != LENGTH_BLOCK_RSA) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// Decrypt with IA private
		PLAIDKey plaidKey = (PLAIDKey)key.value;
		
		try {
			cspRSA.init(plaidKey.iaKeyPrivate, Cipher.MODE_DECRYPT);
			cspRSA.doFinal(buffer, offset, length, buffer, offset);			
		} catch (CryptoException ex) {
			// The most likely reason for this exception is that the key was wrong
			// and so the padding validation failed post-decryption.
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		//
		// EXPECTED FORMAT:
		// FAKEY | FAKEY | DIVDATA
		//
		
		// Verify that FAKEY | FAKEY are a match
		if (0 != Util.arrayCompare(	buffer, offset, 
									buffer, (short)(offset + LENGTH_KEY_AES), 
									LENGTH_KEY_AES)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		// Set our internal transport key
		transportKey.setKey(buffer, offset);		
	}
}
