package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
 
public class OpenPLAIDSAM extends Applet implements ExtendedLength
{
	
	private byte[] commandBuffer;	
	
	/*
	 * PERSISTENT applet variables (EEPROM)
	 */

	private byte[] persistentState;
	private OwnerPIN pin;
	private KeyRecord[] keys;
	private CryptoPLAID cspPLAID;	
	
	/*
	 * Applet constants (Generally not required to change)
	 */
	 
	// Additional SW responses (missing from ISO7816 object)
	public static final short SW_PIN_TRIES_REMAINING = (short)0x63C0;
	
	// Applet Commands - Administrative
	private static final byte INS_SET_DATA			= (byte)0x10;
	private static final byte INS_GET_STATUS		= (byte)0x11;
	private static final byte INS_VERIFY_PIN	 	= (byte)0x12;
	private static final byte INS_RESET_AUTH	 	= (byte)0x13;
	private static final byte INS_ACTIVATE	 		= (byte)0x14;
	private static final byte INS_TERMINATE			= (byte)0x15;
	private static final byte INS_LOAD_KEY	 		= (byte)0x16;
	private static final byte INS_READ_NEXT_KEY		= (byte)0x17;
	
	// Applet Commands - PLAID
	private static final byte INS_PLAID_LOAD_FAKEY 	= (byte)0x81;	
	private static final byte INS_PLAID_SET_DATA 	= (byte)0x82;
	private static final byte INS_PLAID_INITIAL_AUTH= (byte)0x87;
	private static final byte INS_PLAID_FINAL_AUTH  = (byte)0x86;

	//
	// Persistent state definitions
	// 
	 
	// The applet lifecycle state (SELECTABLE, PERSONALISED, TERMINATED
	private static final short OFFSET_APPLET_STATE		= (short)0;
	private static final short LENGTH_APPLET_STATE		= (short)1;

	// The Electronic Serial Number
	private static final short OFFSET_ESN				= (short)(OFFSET_APPLET_STATE + LENGTH_APPLET_STATE);
	private static final short LENGTH_ESN				= Config.LENGTH_ESN;

	// The 'Profile Identifier' value
	// NOTE: This is just used by the application to know which key table has
	//		 been loaded onto this instance (i.e. ENCODE, READ ONLY, etc)
	//		 The OpenPLAIDSAM applet does not use this information at all.
	private static final short OFFSET_PROFILE			= (short)(OFFSET_ESN + LENGTH_ESN);
	private static final short LENGTH_PROFILE			= Config.LENGTH_PROFILE;

	// The 'System Diversifier' value
	private static final short OFFSET_SYSTEM_DIV		= (short)(OFFSET_PROFILE + LENGTH_PROFILE);
	private static final short LENGTH_SYSTEM_DIV		= Config.LENGTH_DIV_SYSTEM;
	
	private static final short LENGTH_PERSISTENT_STATE 	= (short)(	LENGTH_APPLET_STATE + 
																	LENGTH_ESN +
																	LENGTH_PROFILE + 
																	LENGTH_SYSTEM_DIV
																	);
	
	// Application States
	private static final byte STATE_SELECTABLE 			= (byte)0x00;
	private static final byte STATE_PERSONALISED 		= (byte)0x01;	
	private static final byte STATE_TERMINATED 			= (byte)0xFF;	
					
	// Helper constants
	private static final byte ZERO_BYTE		= (byte)0;
	private static final short ZERO_SHORT	= (short)0;
	private static final short LENGTH_BYTE 	= (short)1;
	private static final short LENGTH_SHORT = (short)2;

	
	public OpenPLAIDSAM() {

		// Create our extended length command buffer
		if (Config.FEATURE_EXTENDED_APDU_IN_RAM) {
			// Create it in RAM
			if (Config.FEATURE_CLEAR_ON_RESET) {
				commandBuffer = JCSystem.makeTransientByteArray(Config.LENGTH_COMMAND_BUFFER, JCSystem.CLEAR_ON_RESET);
			} else {
				commandBuffer = JCSystem.makeTransientByteArray(Config.LENGTH_COMMAND_BUFFER, JCSystem.CLEAR_ON_DESELECT);							
			}
		} else {
		
			// Create it in EEPROM
			commandBuffer = new byte[Config.LENGTH_COMMAND_BUFFER];
		}
		
		// Create our persistent state
		persistentState = new byte[LENGTH_PERSISTENT_STATE];

		// Set our initial application state
		persistentState[OFFSET_APPLET_STATE] = STATE_SELECTABLE;
		
		// Create our CSP's
		cspPLAID = new CryptoPLAID();

		// Create our operator PIN
		pin = new OwnerPIN(Config.PIN_RETRIES_MAX, Config.LENGTH_PIN_MAX);	
								   		
		// Generate our key storage container
		keys = new KeyRecord[Config.MAX_KEYS_PLAID];

		short index = 0;

		// Pre-allocate the keys of type PLAID
		for (short i = 0; i < Config.MAX_KEYS_PLAID; i++) {
			keys[index] = new KeyRecord(PLAIDKey.TYPE_PLAID, Config.LENGTH_RSA_KEY_BITS);
			index++;	
		}		
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new OpenPLAIDSAM().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}


	public boolean select() {
		
		// Set the application state to TERMINATED
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) {
			
			// Delete all key material
			for (short i = 0; i < keys.length; i++) {
				keys[i].clearRecord();
			}			
			
			// Prevent selection
			if (Config.FEATURE_PREVENT_SELECT_IF_TERMINATED) {
				return false;				
			}
		}
		
		return true;		
	}

	public void process(APDU apdu)
	{
		// Restrict the OpenPLAIDSAM to the contact interface
		if ( (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) != APDU.PROTOCOL_MEDIA_DEFAULT ) {
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}

		// Ignore the selectingApplet call
		if (selectingApplet()) return;
		
        // Validate the CLA
        if (!apdu.isISOInterindustryCLA()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        /*
         * Handle incoming extended APDU sizes
         */

		short recvBytes = apdu.setIncomingAndReceive();
		
		byte[] buffer = apdu.getBuffer();
		short length = apdu.getIncomingLength();
		short offset = apdu.getOffsetCdata();
		
		// If there is any data to receive
		if (length != 0) {

			// Check to see if we have an extended APDU
			if (recvBytes < length) {
				
				// Clear the command buffer to be safe
				Util.arrayFillNonAtomic(commandBuffer, ZERO_SHORT, Config.LENGTH_COMMAND_BUFFER, (byte)0x00);

				// Write the CAPDU header into our command buffer
				Util.arrayCopyNonAtomic(buffer, ZERO_SHORT, commandBuffer, ZERO_SHORT, offset);

				// Write the initially received bytes into our command buffer
				Util.arrayCopyNonAtomic(buffer, offset, commandBuffer, offset, recvBytes);

				// Offset to write to command buffer			
				short recvOffset = (short)(recvBytes + offset); 
				short bytesRemaining = (short)(length - recvBytes);
				
				while (bytesRemaining != 0) {	
						
					// Retrieve the next allocation of bytes
					recvBytes = apdu.receiveBytes(ZERO_SHORT);

					// Make sure we're not writing past our commandBuffer length
					if ((short)(recvOffset + recvBytes) > Config.LENGTH_COMMAND_BUFFER) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					
					// Copy the bytes into our command buffer
					Util.arrayCopyNonAtomic(buffer, ZERO_SHORT, commandBuffer, recvOffset, recvBytes);					

					// Move the offset forward
					recvOffset += recvBytes; 										
					bytesRemaining -= recvBytes;
					
				} 			
				
				// Point our buffer reference to the commandBuffer instead
				buffer = commandBuffer;
				//apdu.setOutgoing();
				//apdu.setOutgoingLength((short)(length + offset));
				//apdu.sendBytesLong(buffer, ZERO_SHORT, (short)(length + offset));
				//return;
			}
		}
		
		// Call the appropriate process method based on the INS        
		switch (buffer[ISO7816.OFFSET_INS])
		{
			
		// Administrative Commands
		case INS_SET_DATA: length = processSET_DATA(buffer, offset, length); break;
		case INS_GET_STATUS: length = processGET_STATUS(buffer, offset, length); break;
		case INS_VERIFY_PIN: length = processVERIFY_PIN(buffer, offset, length); break;
		case INS_RESET_AUTH: length = processRESET_AUTH(buffer, offset, length); break;
		case INS_ACTIVATE: length = processACTIVATE(buffer, offset, length); break;
		case INS_LOAD_KEY: length = processLOAD_KEY(buffer, offset, length); break;
		case INS_READ_NEXT_KEY: length = processREAD_NEXT_KEY(buffer, offset, length); break;
		case INS_TERMINATE: length = processTERMINATE(buffer, offset, length); break;

		// PLAID Commands
		case INS_PLAID_LOAD_FAKEY: length = processPLAID_LOAD_FAKEY(buffer, offset, length); break;
		case INS_PLAID_SET_DATA: length = processPLAID_SET_DATA(buffer, offset, length); break;
		case INS_PLAID_INITIAL_AUTH: length = processPLAID_INITIAL_AUTH(buffer, offset, length); break;
		case INS_PLAID_FINAL_AUTH: length = processPLAID_FINAL_AUTH(buffer, offset, length); break;
		
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
		// Send any outgoing data
		// NOTES: 		
		// - We are always sending as if sending an extended APDU response.
		// - It is presumed here that the outgoing data is at the start of the apdu buffer
		if (length > 0) {
			apdu.setOutgoing();
			apdu.setOutgoingLength(length);
			apdu.sendBytesLong(buffer, ZERO_SHORT, length);
		}
	}

	/**
	 * Sets the personalisation data for this OpenPLAIDSAM instance
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processSET_DATA(byte[] apdu, short offset, short length) throws ISOException
	{
		final byte P1_ESN 			= (byte)1;
		final byte P1_PIN 			= (byte)2;
		final byte P1_PROFILE 		= (byte)3;
		final byte P1_DIVERSIFIER 	= (byte)4;

		/*
		 * PRE-CONDITIONS
		 */ 
		 
		// PRE-CONDITION 1 - The application life-cycle state must be set to SELECTABLE
		if (persistentState[OFFSET_APPLET_STATE] != STATE_SELECTABLE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The P1 value must be valid (in the list of supported P1 values below)
		switch (apdu[ISO7816.OFFSET_P1]) {
			
		case P1_ESN: 
			
			// PRE-CONDITION 3A - The APDU length must be LENGTH_ESN
			if (length != Config.LENGTH_ESN ) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			// PRE-CONDITION 4A - The supplied ESN must be non-zero
			if (arrayIsZero(apdu, offset, length)) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			
			/*
			 * EXECUTION STEPS
			 */
			 
			// EXECUTION 1A - Update the ESN
			Util.arrayCopyNonAtomic(apdu, offset, persistentState, OFFSET_ESN, Config.LENGTH_ESN);	

			// Done
			break;

		case P1_PIN:
			
			// PRE-CONDITION 3B - The APDU length must be between LENGTH_PIN_MIN and LENGTH_PIN_MAX
			if (length < Config.LENGTH_PIN_MIN || length > Config.LENGTH_PIN_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			// PRE-CONDITION 4B - The supplied PIN must be non-zero
			if (arrayIsZero(apdu, offset, length)) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			
			/*
			 * EXECUTION STEPS
			 */
			 
			// EXECUTION 1B - Update the PIN		 
			pin.update(apdu, offset, (byte)length);		
			
			// EXECUTION 2B - Verify the PIN
			// NOTE: 
			// The reason we do this is because the OwnerPIN object doesn't provide any way to check if
			// it has been set or not! By verifying, we set the PIN's validation status and we can
			// check this when activating.
			if (!pin.check(apdu, offset, (byte)length))
			{
				// Just a sanity check. There's no reason we should ever get here.
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
			
			// Done
			break;

		case P1_PROFILE:
			
			// PRE-CONDITION 3C - The APDU length must be LENGTH_PROFILE
			if (length != LENGTH_PROFILE) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					
			/*
			 * EXECUTION STEPS
			 */
			 
			// EXECUTION 1C - Update the PROFILE
			Util.arrayCopyNonAtomic(apdu, offset, persistentState, OFFSET_PROFILE, LENGTH_PROFILE);
			
			// Done
			break;
			
		case P1_DIVERSIFIER:
			
			// PRE-CONDITION 3D - The APDU length must be between 1 and LENGTH_SYSTEM_DIV - 1 (the first byte is the length)
			if (length < 1 || length >= LENGTH_SYSTEM_DIV) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					
			/*
			 * EXECUTION STEPS
			 */
			 
			// EXECUTION 1D - Update the PROFILE (Set the first byte as the length
			persistentState[OFFSET_SYSTEM_DIV] = (byte)(length & 0xFF);
			Util.arrayCopyNonAtomic(apdu, offset, persistentState, (short)(OFFSET_SYSTEM_DIV + 1), length);
			
			// Done
			break;
			
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
		
		// No response
		return ZERO_SHORT;
	}

	/**
	 * Gets the applet configuration and state
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processGET_STATUS(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITIONS
		 */ 

		// NONE

		/*
		 * EXECUTION STEPS
		 */
		 
		// Reuse these as we don't care about the incoming data
		offset = ZERO_SHORT;
		length = ZERO_SHORT;
		
		// 1. Applet State + Profile + ESN
		Util.arrayCopyNonAtomic(persistentState, ZERO_SHORT, apdu, ZERO_SHORT, LENGTH_PERSISTENT_STATE);
		offset += LENGTH_PERSISTENT_STATE;
		
		if (Config.FEATURE_HIDE_DIV_SYSTEM) {
			
			// 2. Clear the System Diversifier value
			Util.arrayFillNonAtomic(apdu, OFFSET_SYSTEM_DIV, LENGTH_SYSTEM_DIV, (byte)0xFF);			
			
		}
		
		// 3. Reserved
		apdu[offset++] = (byte)0x00;
		
		// 4. PLAID Authentication State
		apdu[offset++] = cspPLAID.getAuthState();

		// 5. PIN Authentication State
		
		if (pin.getTriesRemaining() == ZERO_BYTE) {
			// The PIN is blocked
			apdu[offset++] = (byte)0xFF;			
		} else {
			apdu[offset++] = (pin.isValidated()) ? (byte)0x01 : (byte)0x00;						
		}

		// Return the status bytes
		return offset; // The offset variable holds the length of the status bytes
	}

	/**
	 * Resets the current state for all cryptographic service providers and the applet PIN.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processRESET_AUTH(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITIONS
		 */ 
		 
		// 1. The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		// NOTE: We don't bother checking if they are authenticated as this is safe to still execute.

		/*
		 * EXECUTION STEPS
		 */

		// 2. Clear the PIN authentication status
		pin.reset();

		// 3. Clear all authentication context values
		cspPLAID.resetAuthentication();

		// No response
		return ZERO_SHORT;
	}

	/**
	 * Authenticates the host to this SAM via the operator PIN.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processVERIFY_PIN(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITIONS
		 */ 
		 
		// 1. The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// 2. The APDU length must be between LENGTH_PIN_MIN and LENGTH_PIN_MAX
		if (length < Config.LENGTH_PIN_MIN || length > Config.LENGTH_PIN_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		/*
		 * EXECUTION STEPS
		 */
		 
		// EXECUTION STEP 1 - Clear the previous validation (if any)
		pin.reset();
		
		// EXECUTION STEP 2 - Verify the PIN	
		boolean valid = pin.check(apdu, offset, (byte)length);
		
		if (!valid) {
			
			// The check failed, see if we have run out of retries
			if (pin.getTriesRemaining() == 0) {
				// We have run out, terminate the card
				terminateApplet();
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);								
			} else {
				ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
			}			
		}
		
		// The PIN has been successfully validated

		// No response
		return ZERO_SHORT;
	}

	/**
	 * Progresses the applet life-cycle to ST_PERSONALISED.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processACTIVATE(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to SELECTABLE
		if (persistentState[OFFSET_APPLET_STATE] != STATE_SELECTABLE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The ESN must be set (non-zero)
		if (arrayIsZero(persistentState, OFFSET_ESN, LENGTH_ESN)) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);			
		}

		// PRE-CONDITION 3 - The PIN must be set	
		// NOTE: The OwnerPIN was previously validated by the SET DATA command during PIN update (see notes in SET DATA)
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 4 - The Profile Identifier must be set (non-zero)
		if (arrayIsZero(persistentState, OFFSET_PROFILE, LENGTH_PROFILE)) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);			
		}

		// PRE-CONDITION 5 - The System Diversifier must be set (length is non-zero)
		if ( persistentState[OFFSET_SYSTEM_DIV] == (byte)0 ) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

		/*
		 * EXECUTION STEPS 
		 */

		// EXECUTION STEP 1 - Set the application state to PERSONALISED
		persistentState[OFFSET_APPLET_STATE] = STATE_PERSONALISED;

		// EXECUTION STEP 2 - Clear the PIN authentication status
		pin.reset();

		// No response
		return ZERO_SHORT;
	}

	/**
	 * Progresses the applet life-cycle to ST_TERMINATED and erases all key material.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processTERMINATE(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PIN must be authenticated
		// NOTE: 
		// Considering a host can just supply a PIN wrong [n] times and the card will still terminate, there
		// isn't much benefit in checking this except as a sanity check. Still, we retain it for down the track
		// when we add PUK functionality.
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		/*
		 * EXECUTION STEPS 
		 */

		// Perform in doTerminate() so it can be executed from other parts of the applet
		terminateApplet();

		// No response
		return ZERO_SHORT;
	}

	/**
	 * This command loads keys into the key storage container of the SAM, ready for use.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processLOAD_KEY(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to SELECTABLE
		if (persistentState[OFFSET_APPLET_STATE] != STATE_SELECTABLE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - P1 must be set to a valid key type
		// NOTE: We don't worry about limiting this value to the list of actually supported key types
		// 		 as the slot availability step will always fail if given an invalid key type.

		// PRE-CONDITION 3 - The APDU data must be at least the size of LENGTH_HEADER
		// NOTE: The individual key type functions will check their required lengths
		if (length < KeyRecord.LENGTH_HEADER) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);				

		// PRE-CONDITION 4 - The record envelope must be valid
		/*
		 * IMPLEMENTATION NOTE:
		 * It is not currently in scope to encrypt and/or MAC the key export records, as it assumed
		 * it will be held in 3-part export format in a trusted high-security storage.
		 *
		 * Nonetheless, it is noted here that this would be a reasonably straight-forward process to
		 * implement.
		 */

		// PRE-CONDITION 5 - There must be no existing keys with this key identifier.
		// TODO: Implement duplicate detection (by ID and Version)

		// PRE-CONDITION 6 - There must be an available slot for this key type		
		// NOTE: This is evaluated in the execution cases below.		
		
		// PRE-CONDITION 7 - 
		
		/*
		 * EXECUTION STEPS 
		 */

		short index = -1;				
			
		// EXECUTION STEP 1 - Find an available key slot of the type specified in P1
		for (short i = 0; i < keys.length; i++) {
			if ((keys[i].value.getType() == apdu[ISO7816.OFFSET_P1] ) && !keys[i].value.isInitialized() ) {
				// We found an empty space of the appropriate type
				index = i;
				break;
			}
		}

		// No key slot was found
		if (index < 0) ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		// EXECUTION STEP 2 - Set the key record
		keys[index].setRecord(apdu, offset, length, apdu[ISO7816.OFFSET_P2]);
		
		// EXECUTION STEP 3 - Return the index that was written to
		Util.setShort(apdu, ZERO_SHORT, index);
		return LENGTH_SHORT;
	}

	/**
	 * This command interrogates the SAM key storage for the next available key, from the given key table index.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processREAD_NEXT_KEY(byte[] apdu, short offset, short length)
	{		
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if ((persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED)) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PIN must be authenticated
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		// PRE-CONDITION 3 - P1/P2 must point to a valid 16-bit key index
		short index = Util.getShort(apdu, ISO7816.OFFSET_P1);
		if (index < 0 || index >= keys.length) ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

		// PRE-CONDITION 4 - There must be at least one initialised key from the specified key index
		boolean found = false;
		for (short i = index; i < keys.length; i++) {			
			if (keys[i].value.isInitialized()) {
				// We found a valid key!
				found = true;
				index = i; // Update the index
				break;
			}			
		}
		
		// No more keys
		if (!found) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

		/*
		 * EXECUTION STEPS 
		 */

		// EXECUTION STEP 1 - Copy the found key index to the output buffer
		Util.setShort(apdu, ZERO_SHORT, index);

		// EXECUTION STEP 2 - Copy the record header to the output buffer and return the # of bytes to transmit
		short responseLength = keys[index].getHeader(apdu, LENGTH_SHORT);

		responseLength += LENGTH_SHORT;
		
		return responseLength;
	}

	private short processPLAID_LOAD_FAKEY(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PIN must be authenticated
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		// PRE-CONDITION 3 - The data length must be greater than zero
		if (length <= ZERO_SHORT) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// PRE-CONDITION 4 - P1/P2 must point to a valid 16-bit key index
		short index = Util.getShort(apdu, ISO7816.OFFSET_P1);
		if (index >= keys.length) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		
		// PRE-CONDITION 5 - The supplied key index must be an initialised key
		if (!keys[index].value.isInitialized()) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

		// PRE-CONDITION 6 - The supplied key must be of type TYPE_PLAID
		// NOTE: This is checked by the PLAID CSP internally.
		
						
		/*
		 * EXECUTION STEPS 
		 */
		
		// STEP 1 - Execute the loadFAKey command
		cspPLAID.loadFAKey(keys[index], apdu, offset, length);
		
		// No response
		return ZERO_SHORT;
	}
	
	private short processPLAID_SET_DATA(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PIN must be authenticated
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		// PRE-CONDITION 3 - The PLAID authentication status must be AUTH_OK
		// This is checked inside the CSP method
		
		// PRE-CONDITION 4 - The PLAID authentication keyset must have the PLAID_KEK attribute set
		// This is checked inside the CSP method
		
		/*
		 * EXECUTION STEPS 
		 */
		
		// STEP 1 - Execute the PLAID setData command
		short responseLength = cspPLAID.setData(keys, apdu, offset, length, apdu, ZERO_SHORT);
		
		// Done
		return responseLength;
	}

	/***
	 * Executes the PLAID 'Initial Authenticate' ICC algorithm
	 * 
	 * @param apdu The buffer used for the incoming C-APDU and outgoing R-APDU
	 * @param offset The starting position of the DATA apdu element
	 * @param length The length of the DATA apdu element
	 */
	private short processPLAID_INITIAL_AUTH(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PIN must be authenticated
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		// PRE-CONDITION 3 - The data length must be greater than zero
		if (length <= ZERO_SHORT) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// PRE-CONDITION 4 - P1/P2 must point to a valid 16-bit key index
		short index = Util.getShort(apdu, ISO7816.OFFSET_P1);
		if (index >= keys.length) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		
		// PRE-CONDITION 5 - The supplied key index must be an initialised key
		if (!keys[index].value.isInitialized()) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

		// PRE-CONDITION 6 - The supplied key must be of type TYPE_PLAID
		// NOTE: This is checked by the PLAID CSP internally.
		
		/*
		 * EXECUTION STEPS 
		 */
		
		// STEP 1 - Execute the PLAID Initial Authenticate
		short responseLength = cspPLAID.initialAuthenticate(keys[index], apdu, offset, length, apdu, ZERO_SHORT);
		
		// No response
		return responseLength;
	}

	/***
	 * Executes the PLAID 'Final Authenticate' ICC algorithm
	 * 
	 * @param apdu The buffer used for the incoming C-APDU and outgoing R-APDU
	 * @param offset The starting position of the DATA apdu element
	 * @param length The length of the DATA apdu element
	 */
	private short processPLAID_FINAL_AUTH(byte[] apdu, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state must be set to PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The PLAID authentication state must be set to AUTH_STATE_IAKEY
		if (cspPLAID.getAuthState() != CryptoPLAID.AUTH_STATE_IAKEY) {
			cspPLAID.resetAuthentication();
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// PRE-CONDITION 3 - The PIN must be authenticated
		if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		
		/*
		 * EXECUTION STEPS 
		 */
		
		// STEP 1 - Execute the PLAID Final Authenticate
		short responseLength = cspPLAID.finalAuthenticate(apdu, offset, length, apdu, ZERO_SHORT);
		
		// No response
		return responseLength;
	}	



	/*
	 * Helper methods
	 */
	 
	/***
	 * Tests if the entire array is filled with zeroes
	 * 
	 * @param bArray the byte array containing the values to test
	 * @param bOff The starting position to test from
	 * @param bLen The number of bytes to test
	 */
	private boolean arrayIsZero(byte[] bArray, short bOff, short bLen) {

		for (short i = 0; i < bLen; i++) {
			if ( bArray[(short)(bOff + i)] != 0x00 ) return false;
		}
		
		// If we got this far, we must be all zeroes
		return true;
	} 

	/***
	 * Sets the applet lifecycle state to STATE_TERMINATED and
	 * resets all authentication context, session keys and key material
	 */
	private void terminateApplet() {
		
		/*
		 * NOTE:
		 * We don't put this inside a transaction to prevent the situation where an attacker
		 * attempts to verify the pin and then aborts if it takes longer than expected.
		 *
		 * Instead, on application selection the SAM applet will check if the applet state
		 * is STATE_TERMINATED and if so, will ensure the key records are cleared.
		 */
		
		// Set the application state to TERMINATED
		persistentState[OFFSET_APPLET_STATE] = STATE_TERMINATED;	

		// Delete all key material
		for (short i = 0; i < keys.length; i++) {
			keys[i].clearRecord();
		}
		 
		// Clear the authentication context
		cspPLAID.resetAuthentication();
				
		// Clear the authentication status
		pin.reset();
		 
	}
}
