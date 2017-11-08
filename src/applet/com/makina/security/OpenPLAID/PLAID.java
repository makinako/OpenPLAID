package com.makina.security.OpenPLAID;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PLAID {

	//
	// PERSISTENT OBJECTS
	// 

	// Cryptographic Service Providers
	private Cipher cspRSA;
	private Cipher cspAES;
	private MessageDigest cspSHA;	
	private RandomData cspSRNG;
	private RandomData cspPRNG;

	// Keyset table
	private Keyset[] keysets;
	
	// ACSRecord table
	private ACSRecord[] acsRecords;
	
	// AccessRule table
	private AccessRule[] accessRules;	
	
	// DivData element
	private byte[] divData;

	//
	// TRANSIENT OBJECTS
	// 

	// Session state
	private byte[] sessionState;	

	// Session keys
	private AESKey sessionKey;

	//
	// CONSTANTS
	// 

	// Helper constants
	private static final byte ZERO_BYTE		= (byte)0;
	private static final short ZERO_SHORT	= (short)0;
	private static final short LENGTH_BYTE 	= (short)1;
	private static final short LENGTH_SHORT = (short)2;

	// Boolean constants that have identical hamming weights
	private static final short BOOL_TRUE	= (short)0x5A5A;
	private static final short BOOL_FALSE	= (short)0xA5A5;

	private static final short LENGTH_BLOCK_AES = (short)16;
	private static final short LENGTH_KEY_AES 	= Config.LENGTH_FA_KEY;
	private static final short LENGTH_BLOCK_RSA = Config.LENGTH_IA_KEY;
	private static final short LENGTH_KEY_RSA 	= Config.LENGTH_IA_KEY;

	//
	// PLAID authentication states
	// 
	public static final byte AUTH_STATE_NONE 	= (byte)0;
	public static final byte AUTH_STATE_IAKEY 	= (byte)1;
	public static final byte AUTH_STATE_OK 		= (byte)2;	

	//
	// PLAID protocol constants (ISO)
	// 
	private static final short LENGTH_PAYLOAD	= (short)0; // Optional Payloads feature not implemented
	private static final short LENGTH_KEYSET_ID	= (short)2;	
	private static final short LENGTH_OPMODE_ID = (short)2;
	private static final short LENGTH_ACSRECORD = Config.LENGTH_ACSRECORD;
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
	public static final byte OP_ACTIVATE			= (byte)1;
	public static final byte OP_BLOCK				= (byte)2;
	public static final byte OP_UNBLOCK				= (byte)3;
	public static final byte OP_TERMINATE			= (byte)4;
	public static final byte OP_KEY_CREATE			= (byte)5;
	public static final byte OP_KEY_DELETE			= (byte)6;
	public static final byte OP_KEY_DELETE_ALL		= (byte)7;
	public static final byte OP_ACSR_CREATE			= (byte)8;
	public static final byte OP_ACSR_DELETE			= (byte)9;
	public static final byte OP_ACSR_DELETE_ALL		= (byte)10;
	public static final byte OP_PAYLOAD_CREATE		= (byte)11;
	public static final byte OP_PAYLOAD_DELETE		= (byte)12;
	public static final byte OP_PAYLOAD_DELETE_ALL 	= (byte)13;
	public static final byte OP_FACTORY_RESET		= (byte)127;	

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
	public static final byte TAG_PARAM_ID = (byte)1;
	public static final byte TAG_PARAM_KEY = (byte)2;
	public static final byte TAG_PARAM_DATA = (byte)2;
	public static final byte TAG_PARAM_RULES = (byte)3;
	
	/*
	 * Session state definitions
	 */
	 
	// PLAID authentication stage
	private static final short OFFSET_AUTH_STATE 		= (short)0;
	
	// The currently authenticated keyset (if any)
	private static final short OFFSET_KEYSET	 		= (short)1;

	// The command authentication counter used by the SET DATA command
	private static final short OFFSET_AUTH_COUNTER		= (short)3;

	// The value of RND1 between IA and FA
	private static final short OFFSET_RND1		 		= (short)4;
	
	private static final short LENGTH_SESSION_STATE 	= (short)(	LENGTH_BYTE + 		// AUTH_STATE
																	LENGTH_KEYSET_ID + 	// KEYSET
																	LENGTH_BYTE + 		// COUNTER
																	LENGTH_RND1);		// RND1


	/**
	 * Initialises a new CryptoPLAID object and allocates memory for all 
	 * applet-lifetime objects
	 *
	 * @param buffer A buffer for temporary space to use in generating any key material
	 * @param offset The starting offset for buffer
	 */
	public PLAID(byte[] buffer, short offset) {

		//
		// Create the cryptographic service providers
		//

		// NOTE: We're using NOPAD here because we perform our own PKCS1.5 padding (see InitialAuthenticate() comments).
		cspRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false); 			
		cspAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cspSHA = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		cspSRNG = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM); // For nonces
		cspPRNG = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM); // For PKCS1.5 padding

		//
		// Create transient objects
		//
		
		if (Config.FEATURE_CLEAR_ON_RESET) {
			// Create the session state buffer		
			sessionState = JCSystem.makeTransientByteArray(LENGTH_SESSION_STATE, JCSystem.CLEAR_ON_RESET);

			// Create the session keys
			sessionKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, Config.LENGTH_FA_KEY_BITS, false);
		} else {
			// Create the session state buffer		
			sessionState = JCSystem.makeTransientByteArray(LENGTH_SESSION_STATE, JCSystem.CLEAR_ON_DESELECT);

			// Create the session keys
			sessionKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, Config.LENGTH_FA_KEY_BITS, false);		
		}
		
		//
		// Persistent Data Storage
		// 

		// Create the Keyset database
		keysets = new Keyset[Config.COUNT_KEYSETS];
		for (short i = 0; i < Config.COUNT_KEYSETS; i++) {
			keysets[i] = new Keyset(Config.LENGTH_IA_KEY_BITS, Config.LENGTH_FA_KEY_BITS);
		}
		
		// Create the ACSRecord database
		acsRecords = new ACSRecord[Config.COUNT_ACSRECORDS];
		for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
			acsRecords[i] = new ACSRecord(Config.LENGTH_ACSRECORD);
		}
		
		// Create the AccessRule database
		accessRules = new AccessRule[Config.COUNT_ACCESS_RULES];
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
 			accessRules[i] = new AccessRule();
		}
		
		// Allocate DIVDATA
		divData = new byte[LENGTH_DIVDATA];
		
		// Factory reset
		factoryReset(buffer, offset);
	}
	
	public void factoryReset(byte[] buffer, short offset) {

		// Clear any authentication status
		resetAuthentication();
		
		//
		// Personalisation Data Storage
		// 
		
		// Clear the AccessRule database
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
 			accessRules[i].clear();
		}
		
		// Clear the ACSRecord database
		for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
			acsRecords[i].clear();
		}
		
		// Clear the Keyset database
		for (short i = 0; i < Config.COUNT_KEYSETS; i++) {
			keysets[i].clear();
		}
		
		//
		// PRE-PERSO KEY AND DATA GENERATION
		//		
		
		//
		// Create KEY_SHILL
		// NOTE: All we're doing here is creating a dummy public modulus that will pass the Javacard
		//		 validation test. It can never actually be decrypted
		
		// KEY_SHILL_IA
		cspSRNG.generateData(buffer, offset, LENGTH_KEY_RSA);
		buffer[offset] = (byte)0xB0; 
		buffer[(short)(offset + LENGTH_KEY_RSA - 1)] |= (byte)0x01;

		// Set the SHILLKEY to the first keyset record (it always must be the first record)
		keysets[(short)0].id = Config.KEYSET_SHILL;
		keysets[(short)0].iaKey.setModulus(buffer, offset, LENGTH_KEY_RSA);
		keysets[(short)0].iaKey.setExponent(Config.KEY_TRANSPORT_IA_EXPONENT, ZERO_SHORT, Config.LENGTH_IA_EXPONENT);												  

		// KEY_SHILL_FA
		cspSRNG.generateData(buffer, offset, LENGTH_KEY_AES);
		keysets[(short)0].faKey.setKey(buffer, offset);

		//
		// Create KEY_TRANSPORT
		//
		
		// Set the KEY_TRANSPORT_IA to the next available record
		keysets[(short)1].id = Config.KEYSET_ADMIN;
		keysets[(short)1].iaKey.setModulus(Config.KEY_TRANSPORT_IA_MODULUS, ZERO_SHORT, LENGTH_KEY_RSA);		
		keysets[(short)1].iaKey.setExponent(Config.KEY_TRANSPORT_IA_EXPONENT, ZERO_SHORT, (short)Config.KEY_TRANSPORT_IA_EXPONENT.length);		
		
		// KEY_TRANSPORT_FA
		// NOTE: It doesn't matter what we set it to here, as long as we set it to something
		//		 as it will be re-generated in the wrapTransportKey method
		keysets[(short)1].faKey.setKey(buffer, offset);

		// Generate DIVDATA
		cspSRNG.generateData(divData, ZERO_SHORT, LENGTH_DIVDATA);	
						
		/*
		 * TEST VECTOR - DIVDATA
		 * Uncomment the following lines to apply the ISO-25185-1 ISO test vectors as per
		 * http://standards.iso.org/iso/25185/-1/ISO_IEC_25185-1_Annex%20A_TestVectors.rtf		 
		 *
		 * WARNING: THE FOLLOWING IS ONLY TO BE USED DURING PROTOCOL TESTING AND MUST BE
		 * DISABLED IN ALL OTHER CASES !!		 
		 */
		 
		// >> START TEST VECTOR
		if (Config.FEATURE_PLAID_TEST_VECTORS) {
			Util.arrayCopyNonAtomic(Config.ISO_TEST_DIVDATA, ZERO_SHORT, divData, ZERO_SHORT, LENGTH_DIVDATA);		
		}
		// << END TEST VECTOR		 

		// Generate the SHILL ACSRecord
		acsRecords[(short)0].id = -1;
		cspSRNG.generateData(buffer, offset, LENGTH_ACSRECORD);
		acsRecords[(short)0].setData(buffer, offset);		
	}
	
	public short initialAuthenticate(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
			
        // Clear any existing authentication state
		resetAuthentication();
			
		/*
		 * Command Evaluation (From ISO 25185-1 6.2)
		 */
		 
		// a) The ICC parses the BER-TLV listing of KeySetID values and retrieves 
		//    the first IAKey found which matches a KeySetID supported by the ICC.	
		// b) The ICC should traverse the entire list of KeySetID values irrespective 
		//    of when a keyset match is found. This serves to prevent potential timing attack		
		// c) If non`e of the KeySetID values identified match a key stored by the ICC then the 
		//    ICC responds as per step 3 using a random byte string encrypted with the ShillKey, 
		//    thereby preventing any indication that an error has occurred.
		
		// 
		// NOTE:
		// As mentioned in the standard, this process is susceptable to timing/fingerprinting attacks, 
		// where an attacker could craft IA requests and measure response times with clock 
		// accuracy. The process below aims to 'flatten' the code so that it does the same
		// number of operations regardless of whether a valid keyset was found or not.
		// The process is as follows:
		// - Ensure the shill key is always the first entry in the keyset array.
		// - Default to the shill key
		// - For each Requested keyset, loop through all Supported keysets
		// - Test if the Requested keyset exists in the Supported keysets and assign if not 
		//   already assigned previously, otherwise, assign your existing value.
		// - When complete, you now have your selected key index (which may be the shill)

		// Set the keyset index default to the shill key
		short index = 0;		
		
		// Find the start of the keyset sequence
		inOffset = TlvReader.find(inBuffer, inOffset, TlvReader.ASN1_SEQUENCE);
		if (TlvReader.TAG_NOT_FOUND == inOffset) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

		// Loop through the terminal-requested keysets
		while ( (inOffset = TlvReader.findNext(inBuffer, inOffset, TlvReader.ASN1_OCTET_STRING)) != TlvReader.TAG_NOT_FOUND ) {
			
			// Loop through the stored keysets, skipping the shill key at 0
			short requestedKeyset = TlvReader.toShort(inBuffer, inOffset);
			
			for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
			  // Change the keyset if we found it and we haven't yet changed
			  // NOTE: 
			  // - It's important here that the conditional AND operator (&&) is not used
			  //   here, because && will short-circuit evaluate (not evaluate the second condition
			  //   if the first one is false), leading to timing differences.
			  // - This ternary operator is used so that no matter what the outcome, an
			  //   assignment will be made. 
			  index = ( (requestedKeyset == keysets[i].id) & (index == 0) ) ? i : index;
			}
		}
		
		// Pre-initialise both our RSA and AES CSP's to handle IA and FA operations
		// NOTE: There is no need to diversify the FAKEY here, as it is pre-computed during load.		
		cspRSA.init(keysets[index].iaKey, Cipher.MODE_ENCRYPT);
		cspAES.init(keysets[index].faKey, Cipher.MODE_DECRYPT);

		// Record the authenticating keyset
		Util.setShort(sessionState, OFFSET_KEYSET, keysets[index].id);

		/*
		 * Response Processing (From ISO 25185-1 6.3)
		 */

		// NOTE: Most likely the inBuffer is the same as the outBuffer. That's cool from this point on.
		
		// a) The ICC generates a random value (RND1) using its RNG. The size of RND1 is 
		//    identical to the key size of the selected AES-128 cipher (16 bytes).
		// b) The ICC retrieves the unique diversification data DivData.
		// c) The ICC creates the bit string STR1: KeySetID || DivData || RND1 || RND1.
		
		//
		// Padding
		// NOTE:
		// We pre-compute the padding here for several reasons. Firstly, we know exactly how long
		// the message is so we can do it quickly, but mainly, if we supply a block-aligned data 
		// length to the Cipher instance, we can write the result back to the same location (See
		// the doFinal() description in javacardx.crypto.Cipher)
		// 
		// FORMAT:
		// 00 || 02 || PS || 00 || M
		// 
		// WHERE: 
		// PS is 8 Pseudo-random generated bytes (must be non-zero) of length BLOCK_LENGTH - 3 - [M]
		// M is the message to be encrypted

		short offset = outOffset;
		
		final short LENGTH_PS = (short)(LENGTH_BLOCK_RSA - 3 - LENGTH_STR1);

		outBuffer[offset++] = (byte)0x00; // Leading octet (ensures the data is less than the modulus)
		outBuffer[offset++] = (byte)0x02; // Block Type (Encryption with public key)

		// PS
		cspPRNG.generateData(outBuffer, offset, LENGTH_PS);
		for (short i = 0; i < LENGTH_PS; i++) { // Ensure there are no 00 values here
			// NOTE: Actually it's good that this introduces an aspect of non-determinism here
			//		 because the variable processing times help mask keyset fingerprinting attacks
			if (outBuffer[offset] == ZERO_BYTE) outBuffer[offset]++; // Increment zero to 1
			offset++;
		}
		outBuffer[offset++] = (byte)0x00; // Trailing octet (indicates end of padding)

		// 
		// M
		//
		
		// Keyset Id
		Util.setShort(outBuffer, offset, keysets[index].id);
		offset += LENGTH_KEYSET_ID;
		
		// DivData
		Util.arrayCopyNonAtomic(divData, ZERO_SHORT, outBuffer, offset, LENGTH_DIVDATA);		
		offset += LENGTH_DIVDATA;

		// RND1 + RND1 (Generate first)
		cspSRNG.generateData(sessionState, OFFSET_RND1, LENGTH_RND1);
		Util.arrayCopyNonAtomic(sessionState, OFFSET_RND1, outBuffer, offset, LENGTH_RND1);
		offset += LENGTH_RND1;
		Util.arrayCopyNonAtomic(sessionState, OFFSET_RND1, outBuffer, offset, LENGTH_RND1);		
		
		/*
		 * TEST VECTOR - RND1
		 *
		 * WARNING: THE FOLLOWING IS ONLY TO BE USED DURING PROTOCOL TESTING AND MUST BE
		 * DISABLED IN ALL OTHER CASES !!		 
		 */
		 
		// >> START TEST VECTOR
		if (Config.FEATURE_PLAID_TEST_VECTORS) {		
			Util.arrayCopyNonAtomic(Config.ISO_TEST_RND1, ZERO_SHORT, sessionState, OFFSET_RND1, LENGTH_RND1);		
			offset -= LENGTH_RND1;
			Util.arrayCopyNonAtomic(Config.ISO_TEST_RND1, ZERO_SHORT, outBuffer, offset, LENGTH_RND1);		
			offset += LENGTH_RND1;
			Util.arrayCopyNonAtomic(Config.ISO_TEST_RND1, ZERO_SHORT, outBuffer, offset, LENGTH_RND1);		
		}
		// << END TEST VECTOR

		
		// d) The ICC computes the bit string eSTR1 where eSTR1 = RSAEncryptIAKey (STR1). 
		//    This encryption only uses the modulus and public exponent of the IAKey. 
		//    PKCS1.5 padding shall be incorporated in the encryption.
		cspRSA.doFinal(outBuffer, outOffset, LENGTH_BLOCK_RSA, outBuffer, outOffset);
		
		//
		// Shill Key statistical attack
		// In the report 'Unpicking PLAID', a fingerprinting attack was described that would
		// allow an attacker to profile the shill key over many bad transactions.
		// This attack exploits a property of RSA encryption where the value of the modulus
		// has a bearing on the resulting ciphertext.
		//
		// To work around this, we introduce a level of noise in the resulting ciphertext
		// by randomly re-generating the first byte to a value >= 0x80.
		// This is implemented in such a way that the number of operations are identical
		// regardless of whether the shill key is involved or not.
		//
		
		// i. Generate a random 
		// TODO

		// Update our internal authentication state
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_IAKEY;
		
		// e) The ICC transmits the string eSTR1 to the IFD.
		return LENGTH_BLOCK_RSA;
	}
	
	public short finalAuthenticate(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
		
		// The PLAID authentication status must be AUTH_STATE_IAKEY
		if (sessionState[OFFSET_AUTH_STATE] != AUTH_STATE_IAKEY) {
			resetAuthentication();
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		// Temporarily reset our authentication state, so any error makes us start again
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;

		/*
		 * Command Evaluation (From ISO 25185-1 6.6)
		 */
		
		// a) The ICC calculates STR2 where STR2 = AESDecryptFAKey(Div) (eSTR2). The FAKey(Div) to be 
		//	  used is referenced by the KeySetID used in the earlier IA Response.
		cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
		
		// Remove the M2 padding, this also serves as a basic validation of the decryption
		// as it will fail if it doesn't see the mandatory 0x80 padding byte as a minimum
		if (Config.FEATURE_STRICT_ISO9797_M2_PADDING) {
			inLength = iso9797M2Remove(outBuffer, outOffset, inLength);
		}
		
		// Retrieve the opModeId
		short opModeId = Util.getShort(outBuffer, outOffset);
		outOffset += LENGTH_OPMODE_ID; // Move to RND2
		
		// b) The ICC calculates KeysHash as SHA-256 [RND1||RND2] using RND1 generated in the previous 
		//	  IA Command step and RND2 extracted from STR2.

		// RND1
		cspSHA.reset();
		cspSHA.update(sessionState, OFFSET_RND1, LENGTH_RND1);
		
		// RND2, writing the output to the end of the incoming buffer
		// NOTE: The SHA CSP will produce 32 bytes of output, but we only compare LENGTH_KEYSHASH
		cspSHA.doFinal(	outBuffer, outOffset, LENGTH_RND2, 
						outBuffer, (short)(outOffset + LENGTH_RND2 + LENGTH_KEYSHASH));
			
		// c) The ICC compares KeysHash with the KeysHash extracted from STR2. If a mismatch occurs then 
		//	  the ICC responds using a random byte string encrypted with the ShillKey, thereby preventing 
		//	  any indication that an error has occurred.
		// NOTE: 
		// We don't follow the mismatch condition, as the deviation of logic to produce the random bytes
		// would induce a timing attack where the attacking IFD could send anything for STR2 and measure
		// FinalAuthenticate's response.
		short check = (0 == Util.arrayCompare(
									outBuffer, (short)(outOffset + LENGTH_RND2), 
									outBuffer, (short)(outOffset + LENGTH_RND2 + LENGTH_KEYSHASH), 
									LENGTH_KEYSHASH)) ? BOOL_TRUE : BOOL_FALSE;
		
		// This won't affect timing because it will either always pass or always not evaluate the second condition
		if (Config.FEATURE_FAIL_ON_BAD_AUTH && (BOOL_FALSE == check)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);			
		} 
		
		// Set the session key here
		// NOTE: 
		// - Again for timing attack prevention, we set the session key regardless of whether the
		//	 check succeeded or not. If it didn't, then the value of our KeysHash will make a nicely 
		//	 arbitrary ShillKey value.
		// - KeysHash will be automatically truncated to the key length
		sessionKey.setKey(outBuffer, (short)(outOffset + LENGTH_RND2 + LENGTH_KEYSHASH)); 

		// d) If the optional payload is sent then it is decrypted and processed as required by the 
		//	  implementation rules.

		// NOTE: Optional payload functionality not implemented
		

		/*
		 * Response Processing (From ISO 25185-1 6.7)
		 */

		// a) The ICC retrieves the appropriate fields, based on the OpModeID extracted from STR2. 
		//	  These would normally be the appropriate Wiegand, ID or UUID numbers.
		
		// NOTE: We introduce the concept of a 'Shill ACSRecord' here, to keep up appearances if:
		//		 - The KeysHash validation fails; OR
		//		 - The supplied OpMode Id does not exist; OR
		//		 - The authenticating keyset does not have permission to request this ACSRecord
		short acsRecordIndex = 0;
		
		// Find the ACSRecord
		for (short i = 1; i < Config.COUNT_ACSRECORDS; i++) {
			  // NOTES:
			  // - It's important here that the conditional AND operator (&&) is not used
			  //   here, because && will short-circuit evaluate (not evaluate the second condition
			  //   if the first one is false), leading to timing differences.
			  // - This ternary operator is used so that no matter what the outcome, an
			  //   assignment will be made.
			acsRecordIndex = (	 acsRecords[i].isInitialised() & 
								(acsRecords[i].id == opModeId) & 
								(BOOL_TRUE == check) )  
								? i : acsRecordIndex;
		}
	
		// Validation permissions on the ACSRecord
		short keyset = getAuthenticationKeyset();
		
		// If we are using the shill ACSRecord, then permission is automatically given
		check = (acsRecordIndex == 0) ? BOOL_TRUE : BOOL_FALSE;
		
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			check = (
						// Only set to true if it is not already 
						(BOOL_FALSE == check) &
						(
							// Validation Option A: The keyset and opMode both match
							((accessRules[i].keyset == keyset) & (accessRules[i].opMode == opModeId)) | 
							
							// Validation Option B: The administrative keyset was authenticated
							(Config.KEYSET_ADMIN == keyset)
						)
					) ? BOOL_TRUE : check;
		}

		// Decide how to behave based on the FAIL_ON_BAD_OPMODE feature
		if (Config.FEATURE_FAIL_ON_BAD_OPMODE) {
			// The applet is not configured to use the ACS shill key feature
			if ((acsRecordIndex == 0) || (BOOL_FALSE == check)) {				
				// We make no distinction between not finding an ACSRecord 
				// and not having permissions to read it
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);						
			}			
		} else {		
			// If validation failed, return to the SHILL ACSRecord index 
			// (again both conditions result in an assignment)
			acsRecordIndex = (check == BOOL_TRUE) ? acsRecordIndex : 0;		
		}
		
		// Earlier to reduce the number of operations, we incremented outOffset by LENGTH_OPMODE_ID
		// now we revert back to the original outOffset the caller supplied
		outOffset -= LENGTH_OPMODE_ID;
		
		// b) The ICC creates the bit string STR3: ACSRecord || <Payload>|| DivData
		short offset = outOffset; // Store the outOffset

		// ACSRecord
		Util.arrayCopyNonAtomic(acsRecords[acsRecordIndex].data, ZERO_SHORT, 
								outBuffer, offset, (short)acsRecords[acsRecordIndex].data.length);
		offset += (short)acsRecords[acsRecordIndex].data.length;

		// Payload
		// NOTE: Optional Payload functionality not implemented
		offset += LENGTH_PAYLOAD;
		
		// DivData
		Util.arrayCopyNonAtomic(divData, ZERO_SHORT, outBuffer, offset, LENGTH_DIVDATA);
		offset += LENGTH_DIVDATA;
		
		// c) If needed, padding shall consist of one mandatory byte set to 0x80 followed, if 
		//	  required, by 0 to k–1 bytes set to 0x00, until the respective data block is filled up 
		//    to k bytes, complying with ISO/IEC 9797-1 padding method 2.
		// 
		// NOTE: ISO9797-1 Padding Method 2 requires the 0x80 to be written, regardless of whether
		// 	     the input data is block-aligned or not, so we ignore the 'if needed' statement above.		
		short outLength = (short)(offset - outOffset); // Remove the initial outOffset to leave the length		
		outLength = iso9797M2Add(outBuffer, outOffset, outLength);

		// d) The ICC calculates eSTR3 where eSTR3 = AESEncryptKeysHash (STR3). The cipher mode for 
		//    this operation shall be CBC.
		cspAES.init(sessionKey, Cipher.MODE_ENCRYPT);
		short responseLength = cspAES.doFinal(outBuffer, outOffset, outLength, outBuffer, outOffset);

		// We are now authenticated, update our internal auth state
		sessionState[OFFSET_AUTH_STATE] = AUTH_STATE_OK;

		// e) The ICC transmits the Final Authenticate string eSTR3 to the IFD.
		return responseLength;
	}

	public void resetAuthentication() {
				
		// Reset the authentication state
		sessionKey.clearKey();
		
		// NOTE: This will implicitly set the AUTH_STATE to STATE_NONE (which must always be 0)
		Util.arrayFillNonAtomic(sessionState, ZERO_SHORT, LENGTH_SESSION_STATE, ZERO_BYTE);
		
		// Overwrite OFFSET_KEYSET so that it doesn't default to the ADMIN key
		// (Mitigation against fault analysis / escalation of privilege attacks)
		Util.arrayFillNonAtomic(sessionState, OFFSET_KEYSET, LENGTH_KEYSET_ID, (byte)0xFF);
	}
	
	public void terminate() {		

		// Clear the authentication state (all transient)
		resetAuthentication();

		// Keysets
		keyDeleteAll(true);

		// Delete all ACSRecords
		acsrDeleteAll();
		
		// NOTE: All AccessRules are automatically cleared by the above		
	}
	
	/**
	 * Provides management functionality for PLAID personalisation data.
	 * Commands are sent in encrypted BER-TLV format.
	 *
	 * @param inBuffer The incoming APDU buffer
	 * @param inOffset The offset in the incoming APDU buffer
	 * @param inLength The length of the incoming APDU buffer
	 * @param outBuffer The buffer to write to
	 * @param outOffset The offset to start writing to in the output buffer
	 *
	 * @return The offset to the start of the outBuffer where the command begins
	 */
	public short unwrapCommand(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

		// Ensure that we are authenticated
		if (sessionState[OFFSET_AUTH_STATE] != AUTH_STATE_OK) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        // Ensure that we are authenticated with the ADMIN keyset
        if (getAuthenticationKeyset() != Config.KEYSET_ADMIN) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		//
		// Framing
		// 

		// Make sure the payload length is block-aligned
		if ((inLength == 0) || (inLength % LENGTH_BLOCK_AES != 0)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	

		// Decrypt the payload using the authenticated session key
		cspAES.init(sessionKey, Cipher.MODE_DECRYPT);
		short length = cspAES.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);		

		// Remove the padding (ISO9797 Padding Method 2)
		length = iso9797M2Remove(outBuffer, outOffset, length);

		// Make sure the decrypted length is greater than our hash size
		if (length <= LENGTH_OP_HASH) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		// Validate the trailing hash
		cspSHA.reset();
		cspSHA.doFinal(outBuffer, outOffset, (short)(length - LENGTH_OP_HASH), outBuffer, (short)(outOffset + length)); // Write to the end
		if (0 != Util.arrayCompare(outBuffer, (short)(outOffset + length - LENGTH_OP_HASH), outBuffer, (short)(outOffset + length), LENGTH_OP_HASH)) {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}

		//
		// HACK: Because of the current TLV parser implementation, we erase the 
		// hash value here so that the parser doesn't see it as a possible continuation
		// of the data.
		//
		Util.arrayFillNonAtomic(outBuffer, (short)(outOffset + length - LENGTH_OP_HASH), LENGTH_OP_HASH, ZERO_BYTE);
		
		// We now have an decrypted and authenticated command payload

		// 
		// COMMAND VALIDATION
		// 

		// Validate the SEQUENCE
		outOffset = TlvReader.find(outBuffer, outOffset, TlvReader.ASN1_SEQUENCE);
		if (TlvReader.TAG_NOT_FOUND == outOffset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

		// Read and validate the counter
		outOffset = TlvReader.findNext(outBuffer, outOffset, TlvReader.ASN1_INTEGER);
		if (TlvReader.TAG_NOT_FOUND == outOffset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);				

		if (TlvReader.toByte(outBuffer, outOffset) != sessionState[OFFSET_AUTH_COUNTER]) {
			// The counter does not match! Reset our authentication status and abort
			resetAuthentication();		
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		// Increment our internal counter and write it back
		sessionState[OFFSET_AUTH_COUNTER]++;

		// See if we have exceeded our per-session command counter
		if (sessionState[OFFSET_AUTH_COUNTER] >= Config.MAX_COMMAND_COUNTER) {
			resetAuthentication();
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		// Move to the Operation field and return
		outOffset = TlvReader.findNext(outBuffer, outOffset, TlvReader.ASN1_ENUMERATED);
		if (TlvReader.TAG_NOT_FOUND == outOffset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		// Return the new offset pointing to the start of the decrypted command
		return outOffset;
	}

	/***
	 * Either adds a new keyset or updates an existing one. In addition,
	 * it sets access control rules for which ACSRecords the keyset may access.
	 *
	 * @param id The key identifier to create
	 * @param buffer The buffer containing the key value
	 * @param modulusOffset The offset in the buffer for the RSA modulus
	 * @param exponentOffset The offset in the buffer for the RSA public exponent
	 * @param faOffset The offset for the Final Authenticate key
	 * @param ruleOffset The offset for the access control rules
	 */
	public void keyCreate(short id, byte[] buffer, short modulusOffset, short exponentOffset, short faOffset, short ruleOffset) {
				
		//
		// Parameter validation
		//
		
		// 1 - Ensure that the shill key is not being requested
		if (id == Config.KEYSET_SHILL) {
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		}
		
		// 2 - Check if this record exists (skipping the SHILL key position)
		short index = (short)-1;
		for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
			if (keysets[i].id == id) index = i;
		}
		
		// 3 - If it does not exist, find an empty slot (skipping the SHILL key position)
		if (index < 0) {
			for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
				if (!keysets[i].isInitialised()) {
					index = i;
					break;
				}
			}		 
		}

		// 4 - If no empty slot was found, return an exception
		if (index < 0) ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		//
		// Command execution
		//
		
		// 1 - Clear any existing value
		if (keysets[index].isInitialised()) keysets[index].clear();
		
		// 2 - Create the key record
		keysets[index].id = id;
		keysets[index].iaKey.setModulus(buffer, modulusOffset, LENGTH_KEY_RSA);
		keysets[index].iaKey.setExponent(buffer, exponentOffset, Config.LENGTH_IA_EXPONENT);
		keysets[index].faKey.setKey(buffer, faOffset);
		
		// 3 - Delete any existing access rules associated with this keyset, if any
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			if (accessRules[i].isSet() && accessRules[i].keyset == id) {
				accessRules[i].clear();
			}
		}
		
		// 4 - Set the new access rules (we know there is at least one)
		while (TlvReader.TAG_NOT_FOUND != 
				(ruleOffset = TlvReader.findNext(buffer, ruleOffset, TlvReader.ASN1_OCTET_STRING))) {
					
			// Read the opMode
			short opMode = TlvReader.toShort(buffer, ruleOffset);
			
			// Check that the rule pair doesn't already exist
			for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
				if (accessRules[i].isSet() && accessRules[i].keyset == id && accessRules[i].opMode == opMode) {
					// Since we previously cleared all existing access rules associated with this
					// keyset id, the only reason for a duplicate is that the command supplied multiple
					// duplicates. This is an exceptional scenario and we should fail.
					keysets[index].clear();
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
			}
			
			// Find an empty slot
			index = -1;
			for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
				if (!accessRules[i].isSet()) {
					index = i;
					break;
				}
			}
			
			// If no empty slot was found, return an exception
			if (index < 0) ISOException.throwIt(ISO7816.SW_FILE_FULL);
			
			// Set the rule
			accessRules[index].set(id, opMode);
		};
		
		// 5 - If the updated keyset was KEYSET_ADMIN, reset our authentication
		if (Config.KEYSET_ADMIN == id) resetAuthentication();		
	}	
	
	/***
	 * Deletes an existing keyset from the key storage container, if present
	 *
	 * @param id The key identifier
	 */
	public void keyDelete(short id) {
		
		//
		// Parameter validation
		//
		
		// 1 - The requested key cannot be the ADMIN key
		if (id == Config.KEYSET_ADMIN) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		// 2 - The requested key cannot be the SHILL key
		if (id == Config.KEYSET_SHILL) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		//
		// Command execution
		//

		// 1 - Clear all Access Rules relating to this keyset id
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			if (accessRules[i].keyset == id) accessRules[i].clear();				
		}
		
		// 2 - Find and clear the key entry (skipping the SHILL key position)
		for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
			if (keysets[i].id == id) keysets[i].clear();
		}
	}	

	public void keyDeleteAll(boolean includeAdmin) {
		
		//
		// Parameter validation
		//
		
		// NONE

		//
		// Command execution
		//
		
		// 1 - Clear all Access Rules (excluding KEYSET_ADMIN if not requested)
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			if (!includeAdmin && (accessRules[i].keyset == Config.KEYSET_ADMIN)) continue;
			accessRules[i].clear();				
		}
		
		// 2 - Clear all keysets EXCEPT for KEYSET_SHILL (and KEYSET_ADMIN if not requested)
		for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
			if (!includeAdmin && (keysets[i].id == Config.KEYSET_ADMIN)) continue;
			if (keysets[i].id == Config.KEYSET_SHILL) continue;
			keysets[i].clear();				
		}		
	}
	
	public void acsrCreate(short id, byte[] buffer, short dataOffset) {
		
		//
		// Parameter validation
		//
		
		// 1 - Check that the id is greater than 0
		if (id < 0) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		
		// 2 - Check if this record exists
		short index = (short)-1;
		for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
			if (acsRecords[i].isInitialised() && acsRecords[i].id == id) index = i;
		}
		
		// 3 - If it does not exist, find an empty slot
		if (index < 0) {
			for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
				if (!acsRecords[i].isInitialised()) {
					index = i;
					break;
				}
			}		 
		}

		// 3 - If no empty slot was found, return an exception
		if (index < 0) ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		//
		// Command execution
		//
		
		acsRecords[index].id = id;
		acsRecords[index].setData(buffer, dataOffset);
	}	
	
	public void acsrDelete(short id) {
		
		//
		// Parameter validation
		//
		
		// NONE
		// NOTE: We don't care if we are asked to delete a record that doesn't exist
		
		//
		// Command execution
		//

		// 1 - Clear all Access Rules relating to this id
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			if (accessRules[i].opMode == id) accessRules[i].clear();				
		}
		
		// 2 - Find and clear the ACSRecord entry
		for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
			if (acsRecords[i].id == id) acsRecords[i].clear();
		}		
	}	
	
	public void acsrDeleteAll() {
				
		//
		// Parameter validation
		//
		
		// NONE

		//
		// Command execution
		//
		
		// 1 - Clear all Access Rules
		for (short i = 0; i < Config.COUNT_ACCESS_RULES; i++) {
			accessRules[i].clear();				
		}
		
		// 2 - Clear all ACS Records
		for (short i = 0; i < Config.COUNT_ACSRECORDS; i++) {
			acsRecords[i].clear();
		}		
	}	

	/*
	 * Prepares the transport KEYSET_ADMIN FA Key in a cryptogram
	 *
	 * @param outBuffer The buffer to write the cryptogram to
	 * @param outOffset The starting position to write the cryptogram to
	 * @returns The length of the cryptogram
	 */
	public short wrapTransportKey(byte[] outBuffer, short outOffset) {

		// Find the KEYSET_ADMIN record (skipping the SHILL)
		short index = -1;
		for (short i = 1; i < Config.COUNT_KEYSETS; i++) {
			if (keysets[i].id == Config.KEYSET_ADMIN) {
				index = i;
				break;
			}
		}

        // This should never occur
		if (index < 0) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		//
		// Padding
		// NOTE:
		// We pre-compute the padding here for several reasons. Firstly, we know exactly how long
		// the message is so we can do it quickly, but mainly, if we supply a block-aligned data 
		// length to the Cipher instance, we can write the result back to the same location (See
		// the doFinal() description in javacardx.crypto.Cipher)
		// 
		// FORMAT:
		// 00 || 02 || PS || 00 || M
		// 
		// WHERE: 
		// PS is 8 Pseudo-random generated bytes (must be non-zero) of length BLOCK_LENGTH - 3 - [M]
		// M is the message to be encrypted
		
		
		short offset = outOffset;		
		final short LENGTH_DATA = (short)(LENGTH_KEY_AES + LENGTH_KEY_AES + LENGTH_DIVDATA);
		final short LENGTH_PS = (short)(LENGTH_BLOCK_RSA - 3 - LENGTH_DATA);

		outBuffer[offset++] = (byte)0x00; // Leading octet (ensures the data is less than the modulus)
		outBuffer[offset++] = (byte)0x02; // Block Type (Encryption with public key)

		// PS
		cspPRNG.generateData(outBuffer, offset, LENGTH_PS);
		for (short i = 0; i < LENGTH_PS; i++) { // Ensure there are no 00 values here
			if (outBuffer[offset] == ZERO_BYTE) outBuffer[offset]++; // Increment zero to 1
			offset++;
		}
		outBuffer[offset++] = (byte)0x00; // Trailing octet (indicates end of padding)

		// 
		// M
		// FORMAT: FAKEY | FAKEY | DIVDATA
		//
		// NOTE:
		// The TRANSPORT FA Key value is randomly generated on every call to this method.
		// - First generate the new FA Key
		// - Diversify the FA Key and load it into our internal keyset database
		// - Return the undiversified FA Key to the caller	
		
		// FA_KEY (First)
		cspSRNG.generateData(outBuffer, offset, LENGTH_KEY_AES);

		/*
		 * TEST VECTOR - FA_KEY
		 * WARNING: THE FOLLOWING IS ONLY TO BE USED DURING PROTOCOL TESTING AND MUST BE
		 * DISABLED IN ALL OTHER CASES !!		 
		 */
		 
		// >> START TEST VECTOR
		if (Config.FEATURE_PLAID_TEST_VECTORS) {
			Util.arrayCopyNonAtomic(Config.ISO_TEST_FAKEY, ZERO_SHORT, outBuffer, offset, LENGTH_KEY_AES);	
		}
		// << END TEST VECTOR
		
		/*
		 * Diversify the transport FA_KEY
		 * NOTE: The PLAID protocol requires that the IFD hold the master FA_KEY of a
		 *		 given keyset and diversifies it during authentication. In order to
		 * 		 maintain the same logic, we now diversify our transport FA_KEY and
		 *		 store it back.
		 * 		 The implication of this is that if the IFD does not retain the FA_KEY
		 *		 it will need to request it again so the process can repeat itself.
		 */
		 
		// Set a temporary key (we're going to invalidate any existing session last anyway) 
		sessionKey.setKey(outBuffer, offset);
		cspAES.init(sessionKey, Cipher.MODE_ENCRYPT);		

		offset += LENGTH_KEY_AES; // Move to the next FA KEY space to use as temporary output
		
		// Generate FAKey(DivData)
		cspAES.doFinal(divData, ZERO_SHORT, LENGTH_DIVDATA, outBuffer, offset);
		sessionKey.clearKey(); // Clear the intermediate value
		
		// Set it into our internal transport key
		keysets[index].faKey.setKey(outBuffer, offset);

		// FA_KEY (Copy the original, overwriting our temporary buffer)
		Util.arrayCopyNonAtomic(outBuffer, (short)(offset - LENGTH_KEY_AES), outBuffer, offset, LENGTH_KEY_AES);
		offset += LENGTH_KEY_AES;
		
		// DIVDATA
		Util.arrayCopyNonAtomic(divData, ZERO_SHORT, outBuffer, offset, LENGTH_DIVDATA);

		// Compute the cryptogram
		cspRSA.init(keysets[index].iaKey, Cipher.MODE_ENCRYPT);
		cspRSA.doFinal(outBuffer, outOffset, LENGTH_BLOCK_RSA, outBuffer, outOffset);
		
		// Reset our authentication state (which will also overwrite the temp DivKey)
		resetAuthentication();
		
		// Return the number of response bytes
		return LENGTH_BLOCK_RSA;
	}	
	
	public byte getAuthenticationState() {
		return sessionState[OFFSET_AUTH_STATE];
	}
	public short getAuthenticationKeyset() {
		return Util.getShort(sessionState, OFFSET_KEYSET);
	}


	private static short iso9797M2Add(byte[] buffer, short offset, short length) {
		
		final byte CONST_PAD = (byte)0x80;
		
		// Start at the end of the buffer
		short pos = (short)(length + offset);
		
		// Add the padding constant
		buffer[pos++] = CONST_PAD;
		length++;
		
		// Keep adding zeroes until you get to a block length (an empty block will return 1 block)
		while (length < LENGTH_BLOCK_AES || (length % LENGTH_BLOCK_AES != 0)) {
			buffer[pos++] = (byte)0;
			length++;
		}
		
		return length;
	}
	
	private static short iso9797M2Remove(byte[] buffer, short offset, short length) {

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
		
	//
	// PERSONALISATION DATA DEFINITIONS
	//
	
	/**
	 * Describes a PLAID key record
	 */
	private class Keyset {
				
		public short id;
		public RSAPublicKey iaKey;
		public AESKey faKey;

		public Keyset(short iaKeyLen, short faKeyLen) {
			iaKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, iaKeyLen, false);
			faKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, faKeyLen, false);
			id = (short)-1;
		}
		
		public void clear() {
			id = (short)-1;
			iaKey.clearKey();
			faKey.clearKey();
		}
		
		public boolean isInitialised() {
			return (iaKey.isInitialized() && faKey.isInitialized() && (id >= 0));
		}
	}
	
	/**
	 * Describes a PLAID Access Control System Record
	 */
	private class ACSRecord {
		
		public short id;
		public byte[] data;
		private boolean initialised;
		
		public ACSRecord(short length) {
			data = new byte[length];
			initialised = false;
		}
		
		public void setData(byte[] buffer, short offset) {
			Util.arrayCopyNonAtomic(buffer, offset, data, (short)0, Config.LENGTH_ACSRECORD);
			initialised = true;
		}
		
		public void clear() {
			Util.arrayFillNonAtomic(data, ZERO_SHORT, Config.LENGTH_ACSRECORD, ZERO_BYTE);
			initialised = false;
		}
		
		public boolean isInitialised() {
			return initialised;
		}
	}

	/**
	 * A permissions entry that maps a PLAID keyset to an ACSRecord that the keyset may request.
	 */
	private class AccessRule {
		
		public short keyset;		
		public short opMode;
		
		public AccessRule() {
			clear();
		}
		
		public void clear() {
			keyset = (short)-1;
			opMode = (short)-1;
		}
		public void set(short keyset, short opMode) {
			if (keyset < 0 || opMode < 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			this.keyset = keyset;
			this.opMode = opMode;
			
		}
		public boolean isSet() {
			return (keyset >= 0 && opMode >= 0);
		}
	}	
}

