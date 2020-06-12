package com.makina.security.OpenPLAID;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

// IMPLEMENTATION NOTES
// - For personalisation (SET DATA), requires ICCD support for Extended Length apdu
// - For all other operations, standard APDU is all that is required.

public class OpenPLAID extends Applet implements ExtendedLength
{
	/*
	 * TRANSIENT applet variables (RAM)
	 */
	private byte[] commandBuffer;	
	
	/*
	 * PERSISTENT applet variables (EEPROM)
	 */
	private byte[] persistentState;
	private PLAID cspPLAID;
	
	/*
	 * Applet Commands - Administrative (Non-ISO)
	 */
	private static final byte INS_GET_DATA		= (byte)0x81;
	private static final byte INS_SET_DATA		= (byte)0x82;
	private static final byte INS_GET_STATUS	= (byte)0x83;
	private static final byte INS_RESET_AUTH	= (byte)0x84;

	/*
	 * Applet Commands - PLAID (ISO)
	 */
	private static final byte INS_PLAID_INITIAL_AUTH = (byte)0x87;
	private static final byte INS_PLAID_FINAL_AUTH   = (byte)0x86;

	//
	// Persistent state definitions
	// 
	 
	// The applet lifecycle state (SELECTABLE, PERSONALISED, TERMINATED)
	private static final short OFFSET_APPLET_STATE		= (short)0;
	private static final short LENGTH_APPLET_STATE		= (short)1;
	
	private static final short LENGTH_PERSISTENT_STATE 	= (short)1;
	
	// Application States
	private static final byte STATE_SELECTABLE 			= (byte)0x00;
	private static final byte STATE_PERSONALISED 		= (byte)0x01;	
	private static final byte STATE_BLOCKED	 			= (byte)0x02;
	private static final byte STATE_TERMINATED 			= (byte)0x80;

	// Helper constants
	private static final byte ZERO_BYTE		= (byte)0;
	private static final short ZERO_SHORT	= (short)0;
	private static final short LENGTH_BYTE 	= (short)1;
	private static final short LENGTH_SHORT = (short)2;

	public OpenPLAID() {		

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
		// NOTE: The PLAID CSP doesn't internally allocate RAM scratch space as it can just use the APDU 
		//	 	 buffer for most operations. This means that during instantiation we need
		//		 to give it some temporary space it can use to generate shill keys, etc.
		cspPLAID = new PLAID(commandBuffer, ZERO_SHORT);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new OpenPLAID().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	public void process(APDU apdu)
	{
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
				Util.arrayFillNonAtomic(commandBuffer, ZERO_SHORT, Config.LENGTH_COMMAND_BUFFER, ZERO_BYTE);

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
			}
		}

		// Call the appropriate process method based on the INS       
		switch (buffer[ISO7816.OFFSET_INS])
		{                

		case INS_GET_DATA: length = processGET_DATA(apdu, buffer, offset, length); break;
		case INS_SET_DATA: length = processSET_DATA(apdu, buffer, offset, length); break;
		case INS_RESET_AUTH: length = processRESET_AUTH(apdu, buffer, offset, length); break;
		case INS_GET_STATUS: length = processGET_STATUS(apdu, buffer, offset, length); break;
		case INS_PLAID_INITIAL_AUTH: length = processPLAID_INITIAL_AUTH(apdu, buffer, offset, length); break;
		case INS_PLAID_FINAL_AUTH: length = processPLAID_FINAL_AUTH(apdu, buffer, offset, length); break;

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

		// Send any outgoing data
		// NOTES: 		
		// - We are always sending as if sending an extended APDU response.
		// - It is presumed here that the outgoing data is at the start of the apdu buffer
		if (length > ZERO_SHORT) {
			apdu.setOutgoing();
			apdu.setOutgoingLength(length);
			apdu.sendBytesLong(buffer, ZERO_SHORT, length);
		}
	}


	/**************************************************************************
	 * ADMINISTRATIVE METHODS
	 *
	 * These methods are NOT a part of ISO-25185, but rather they are required 
	 * for applet and data/key management.
	 **************************************************************************/

	private boolean isContactInterface(APDU apdu) {
		return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_DEFAULT);
	}
	
	/**
	 * Requests the personalisation data for this instance
	 * 
	 * @param apdu The incoming APDU context
	 * @param buffer A pointer to the APDU buffer
	 * @param offset The position of the first byte of DATA in the APDU buffer
	 * @param length The length of the APDU DATA element
	 */
	private short processGET_DATA(APDU apdu, byte[] buffer, short offset, short length) 
	{
		/*
		 * PRE-CONDITIONS
		 */		

		// PRE-CONDITION 1 - The application life-cycle state must be SELECTABLE
		if (persistentState[OFFSET_APPLET_STATE] != STATE_SELECTABLE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);		

		// PRE-CONDITION 2 - The communications media must be default (contact)
		if ((Config.FEATURE_RESTRICT_ADMIN_TO_CONTACT) && !isContactInterface(apdu)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}

		/*
		 * EXECUTION STEPS
		 */

		short responseLength = cspPLAID.wrapTransportKey(buffer, ZERO_SHORT);		
		return responseLength;
	}
	
	/**
	 * Sets the personalisation data for this instance
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processSET_DATA(APDU apdu, byte[] buffer, short offset, short length) 
	{
		
		//
		// IMPORTANT:
		// Most of the operations below involve multiple persistent memory writes and so
		// need to be wrapped in a transaction to preserve integrity. Because JC 2.2.x does
		// not support nested transactions, we wrap this entire section in a transaction.
		// If the individual methods are called from anywhere else, note that they should
		// be put inside a transaction as they will not initiate one themselves.
		//
		
		/*
		 * PRE-CONDITIONS
		 */		

		// PRE-CONDITION 1 - The application life-cycle state must NOT be set to TERMINATED
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

		// PRE-CONDITION 2 - The communications media must be default (contact)
		if ((Config.FEATURE_RESTRICT_ADMIN_TO_CONTACT) && !isContactInterface(apdu)) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		// PRE-CONDITION 3 - The PLAID authentication state must be set to AUTH_STATE_OK
		// NOTE: This is checked internally by the PLAID unwrapping process

		// PRE-CONDITION 4 - The PLAID authenticated keyset must be KEYSET_ADMIN
		// NOTE: This is checked internally by the PLAID unwrapping process

		// PRE-CONDITION 5 - The command must be unwrapped and pass validation		
		offset = cspPLAID.unwrapCommand(buffer, offset, length, buffer, offset);

		/*
		 * EXECUTION STEPS
		 */

		//
		// Command execution
		//

		// Read the operation (the offset now points to it since unwrapping passed)
		byte operation = TlvReader.toByte(buffer, offset);

		// EXECUTION STEP 2 - Execute the transaction based on the operation		
		switch (operation) {

		case PLAID.OP_ACTIVATE: {

			//
			// Command Execution
			//

			try {
				beginTransaction();				
				activate();
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_BLOCK: {

			//
			// Command Execution
			//

			try {
				beginTransaction();				
				block();
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_UNBLOCK: {

			//
			// Command Execution
			//

			try {
				beginTransaction();				
				unblock();
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_TERMINATE: {

			//
			// Command Execution
			//
			try {
				beginTransaction();				
				terminate();
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
		} break;

		case PLAID.OP_FACTORY_RESET: {

			//
			// Command Execution
			//
			try {
				beginTransaction();				
				factoryReset(buffer, ZERO_SHORT);
				commitTransaction();
			}
			catch (TransactionException ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
		} break;

		case PLAID.OP_KEY_CREATE: {

			//
			// Data Validation
			// 

			// Id
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_ID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short id = TlvReader.toShort(buffer, offset);		

			// Key (SEQUENCE)
			offset = TlvReader.find(buffer, offset, PLAID.TAG_PARAM_KEY);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Key - iaModulus
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_KEYSET_IAMODULUS);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short iaModulusOffset = TlvReader.getDataOffset(buffer, offset);

			// Validate the iaModulus length
			if (TlvReader.getLength(buffer, offset) != 
				Config.LENGTH_IA_KEY) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Key - iaExponent
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_KEYSET_IAEXPONENT);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);			
			short iaExponentOffset = TlvReader.getDataOffset(buffer, offset);

			// Validate the iaExponent length
			if (TlvReader.getLength(buffer, offset) != 
				Config.LENGTH_IA_EXPONENT) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Key - faKey			
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_KEYSET_FAKEY);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short faKeyOffset = TlvReader.getDataOffset(buffer, offset);	

			// Validate the faKey length
			if (TlvReader.getLength(buffer, offset) != 
				Config.LENGTH_FA_KEY) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Access Rules (There must be at least 1)
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_RULES);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short ruleOffset = offset;

			// Validate the Access Rules length (Must be a multiple of 2)
			if ( (TlvReader.getLength(buffer, offset) == 0) ||
				 (TlvReader.getLength(buffer, offset) % LENGTH_SHORT != 0)) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
				 
			// Rules are actually parsed inside the keyCreate method to avoid allocating any arrays here

			//
			// Command Execution
			//

			try {
				beginTransaction();				
				cspPLAID.keyCreate(id, buffer, iaModulusOffset, iaExponentOffset, faKeyOffset, ruleOffset);

				// OPTIONALLY 
				// - If FEATURE_AUTO_ACTIVATE_ON_ADMIN_KEY_CHANGE is true; and
				// - If the state is STATE_SELECTABLE
				// - If the keyset being updated is KEYSET_ADMIN
				// Update the applet state to STATE_PERSONALISED automatically				
				if (Config.FEATURE_AUTO_ACTIVATE_ON_ADMIN_KEY_CHANGE && 
						persistentState[OFFSET_APPLET_STATE] == STATE_SELECTABLE &&
						Config.KEYSET_ADMIN == id) {
					activate();
				}
				
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_KEY_DELETE: {

			//
			// Data Validation
			// 

			// Id
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_ID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short id = TlvReader.toShort(buffer, offset);		

			//
			// Command Execution
			//

			try {
				beginTransaction();				
				cspPLAID.keyDelete(id);
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();				
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_KEY_DELETE_ALL: {

			//
			// Data Validation
			// 

			// NONE

			//
			// Command Execution
			//

			// Delete all keys EXCEPT the admin key (this should only be deleted by for STATE_TERMINATED)
			try {
				beginTransaction();				
				cspPLAID.keyDeleteAll(false);
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;

		case PLAID.OP_ACSR_CREATE: {

			//
			// Data Validation
			// 

			// Id
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_ID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short id = TlvReader.toShort(buffer, offset);		

			// Data
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_DATA);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Validate the data length
			if (TlvReader.getLength(buffer, offset) != 
				Config.LENGTH_ACSRECORD) ISOException.throwIt(ISO7816.SW_FILE_INVALID);

			// Move to the data offset
			offset = TlvReader.getDataOffset(buffer, offset);
			
			//
			// Command Execution
			//

			try {
				beginTransaction();				
				cspPLAID.acsrCreate(id, buffer, offset);
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			
		} break;
		
		case PLAID.OP_ACSR_DELETE: {
			
			//
			// Data Validation
			// 
			
			// Id
			offset = TlvReader.findNext(buffer, offset, PLAID.TAG_PARAM_ID);
			if (TlvReader.TAG_NOT_FOUND == offset) ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			short id = TlvReader.toShort(buffer, offset);		

			//
			// Command Execution
			//
			
			try {
				beginTransaction();				
				cspPLAID.acsrDelete(id);
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}
			
		} break;
		
		case PLAID.OP_ACSR_DELETE_ALL: {
			
			//
			// Data Validation
			// 
			
			// NONE

			//
			// Command Execution
			//
			
			try {
				beginTransaction();				
				cspPLAID.acsrDeleteAll();
				commitTransaction();
			}
			catch (Exception ex) {
				abortTransaction();			
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
			}

		} break;
		
		default:
			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		
		// DONE
		return ZERO_SHORT;
	}

	/**
	 * Gets the applet configuration and state
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processGET_STATUS(APDU apdu, byte[] buffer, short offset, short length)
	{
		/*
		 * PRE-CONDITIONS
		 */ 

		// NONE

		/*
		 * EXECUTION STEPS
		 */
		 
		//
		// Populate the status buffer
		//
		offset = ZERO_SHORT;
				
		// Applet status
		buffer[offset++] = persistentState[OFFSET_APPLET_STATE];
		
		// PLAID authentication status
		buffer[offset++] = cspPLAID.getAuthenticationState();			
		
		return offset; // The offset variable holds the length of the status bytes
	}

	/**
	 * Resets the current state for all cryptographic service providers and the applet PIN.
	 * 
	 * @param apdu The incoming APDU context
	 */
	private short processRESET_AUTH(APDU apdu, byte[] buffer, short offset, short length)
	{
		/*
		 * PRE-CONDITIONS
		 */ 
		 
		// 1. The application life-cycle state must not be set to TERMINATED
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		// NOTE: We don't bother checking if they are authenticated as this is safe to still execute.

		/*
		 * EXECUTION STEPS
		 */

		// 1. Clear all authentication context values
		cspPLAID.resetAuthentication();

		// No response
		return ZERO_SHORT;
	}

	///
	/// 
	///
	private short processPLAID_INITIAL_AUTH(APDU apdu, byte[] buffer, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - If the requested keyset is KEYSET_ADMIN, the application life-cycle state MUST NOT be TERMINATED.
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		// PRE-CONDITION 2 - If the requested keyset is NOT KEYSET_ADMIN, the application life-cycle state MUST be PERSONALISED;		
		// PRE-CONDITION 3 - If the requested keyset is KEYSET_ADMIN, the media used must be DEFAULT (contact interface).
		// NOTE: These are evaluated post-IA because we need the PLAID CSP to tell us which keyset was used.
		
		/*
		 * EXECUTION STEPS 
		 */
		

		// STEP 1 - Execute the PLAID 'Initial Authenticate' command
		short responseLength = 0;
		try	{			
			responseLength = cspPLAID.initialAuthenticate(buffer, offset, length, buffer, ZERO_SHORT);			

			// Now we validate PRE-CONDITION's 2 & 3.
			if (cspPLAID.getAuthenticationKeyset() == Config.KEYSET_ADMIN) {
				// Validate that we are using the contact interface
				if ((Config.FEATURE_RESTRICT_ADMIN_TO_CONTACT) && (!isContactInterface(apdu))) {
					// Reset our authentication status
					cspPLAID.resetAuthentication();
					
					// Fail
					ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
				}
			} else {
				// Validate that we are not in STATE_BLOCKED or STATE_SELECTABLE
				if (persistentState[OFFSET_APPLET_STATE] == STATE_SELECTABLE ||
					persistentState[OFFSET_APPLET_STATE] == STATE_BLOCKED) {				
						// Reset our authentication status
						cspPLAID.resetAuthentication();

						// Fail
						ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);						
					}
			}
		} catch (Exception ex) {
			// Clear our APDU buffer to ensure any intermediate values are wiped.
			// This should normally be guaranteed by the JCRE, but provides an additional
			// measure against the fault injection class of attacks
			Util.arrayFillNonAtomic(buffer, ZERO_SHORT, (short)buffer.length, ZERO_BYTE);
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		// Done
		return responseLength;
	}

	///
	/// 
	///
	private short processPLAID_FINAL_AUTH(APDU apdu, byte[] buffer, short offset, short length)
	{
		/*
		 * PRE-CONDITION STEPS
		 */ 

		// PRE-CONDITION 1 - The application life-cycle state MUST NOT be TERMINATED.
		// NOTE: The initial authenticate process applies more strict criteria to this
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		/*
		 * EXECUTION STEPS 
		 */
		
		// STEP 1 - Execute the PLAID 'Final Authenticate' command
		short responseLength = 0;
		try	{
			responseLength = cspPLAID.finalAuthenticate(buffer, offset, length, buffer, ZERO_SHORT);			
		} catch (Exception ex) {			
			// Clear our APDU buffer to ensure any intermediate values are wiped.
			// This should normally be guaranteed by the JCRE, but provides an additional
			// measure against the fault analysis class of attacks
			Util.arrayFillNonAtomic(buffer, ZERO_SHORT, (short)buffer.length, ZERO_BYTE);
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		// Done
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
	 * Progresses the applet state from SELECTABLE to PERSONALISED.
	 * After this command, the GET DATA instruction will no longer function.
	 */
	private void activate() {
		
		//
		// State validation
		//
		
		// 1 - The application state must be STATE_SELECTABLE
		if (persistentState[OFFSET_APPLET_STATE] != STATE_SELECTABLE) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		//
		// Command execution
		//
		persistentState[OFFSET_APPLET_STATE] = STATE_PERSONALISED;
	}

	/***
	 * Changes the applet state from PERSONALISED to BLOCKED, preventing any 
	 * activity except for administrative authentication and commands.
	 */
	private void block() {
		
		//
		// State validation
		//
		
		// 1 - The application state must be STATE_PERSONALISED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_PERSONALISED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		//
		// Command execution
		//
		
		// 1. Set the applet state to BLOCKED
		persistentState[OFFSET_APPLET_STATE] = STATE_BLOCKED;
				
		// NOTE:
		// Since this command can only be executed by an Administrative authentication,
		// it is not necessary to reset the authentication state.
	}

	/***
	 * Changes the applet state from BLOCKED to PERSONALISED, allowing all normal activity.
	 */
	private void unblock() {
		
		//
		// State validation
		//
		
		// 1 - The application state must be STATE_BLOCKED
		if (persistentState[OFFSET_APPLET_STATE] != STATE_BLOCKED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		//
		// Command execution
		//
		
		// 1. Set the applet state to PERSONALISED
		persistentState[OFFSET_APPLET_STATE] = STATE_PERSONALISED;
			
	}

	/***
	 * Changes the applet state to TERMINATED and erases all host-supplied 
	 * personalisation data. Specifically:
	 * <ul>
	 *	<li> All keys (including the administrative key)
	 * 	<li> All ACSRecord objects
	 * 	<li> All access rules
	 *	<li> Any transient session keys and/or data
	 * </ul>
	 * <p>
	 * Once complete, no further authentications are possible.
	 */
	private void terminate() {
		
		//
		// State validation
		//
		
		// 1 - The application state MUST NOT be STATE_TERMINATED
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		//
		// Command execution
		//

		// 1. Terminate the PLAID CSP
		cspPLAID.terminate();
		
		// 2. Set the applet state to TERMINATED
		persistentState[OFFSET_APPLET_STATE] = STATE_TERMINATED;
		
	}


	/***
	 * Resets the applet back to it's initially installed state, including the transport key.
	 * Note that this does not work if the applet has been terminated.
	 */
	private void factoryReset(byte[] buffer, short offset) {
		
		//
		// State validation
		//
		
		// 1 - The application state MUST NOT be STATE_TERMINATED
		if (persistentState[OFFSET_APPLET_STATE] == STATE_TERMINATED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		//
		// Command execution
		//

		// 1. Terminate the PLAID CSP
		cspPLAID.factoryReset(buffer, offset);
		
		// 2. Set the applet state to SELECTABLE
		persistentState[OFFSET_APPLET_STATE] = STATE_SELECTABLE;
		
	}
	
	
	private void beginTransaction() {
		if (Config.FEATURE_USE_TRANSACTIONS) {
			JCSystem.beginTransaction();
		}
	}
	
	private void commitTransaction() {
		if (Config.FEATURE_USE_TRANSACTIONS) {
			JCSystem.commitTransaction();
		}		
	}
	
	private void abortTransaction() {
		if (Config.FEATURE_USE_TRANSACTIONS) {
			JCSystem.abortTransaction();
		}		
	}
}
