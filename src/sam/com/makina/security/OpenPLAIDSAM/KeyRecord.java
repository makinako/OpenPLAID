package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;
import javacard.security.*;

/**
 *
 * @author kimosullivan
 */
public final class KeyRecord {
        
    /*
     * Key Header
     */

    // The length of the key record header
    public static final short LENGTH_HEADER    	= (short)30;

    // The key identifier (global across all types)
    public static final short OFFSET_ID 		= (short)0;
    public static final short LENGTH_ID			= (short)2;
    
    // The key version (not used, just for reading back)
    public static final short OFFSET_VERSION    = (short)2;
    
    // The key attribute control bitmap
    public static final short OFFSET_KEY_ATTR   = (short)3;
    public static final short LENGTH_KEY_ATTR	= (short)2;

	// The key descriptor
    public static final short OFFSET_NAME   = (short)5;
    public static final short LENGTH_NAME	= (short)25;
	
	
    /*
     * Key attributes (PLAID)
     */
     
    // This key is permitted to perform a PLAID authentication
    public static final short ATTR_PLAID_AUTH    	= (short)(1 << 0);
    
    // This key is permitted to encrypt PLAID key value
    public static final short ATTR_PLAID_KEK      	= (short)(1 << 1);
        
    /*
     * Class variables
     */
    public final byte[] header;
    public final Key value;

    public KeyRecord(byte type, short length) {   
 
        header = new byte[LENGTH_HEADER];

        // Handle special TYPE_PLAID key        
        if (type == PLAIDKey.TYPE_PLAID) {
        	// Ignore the length value and get it from config
	        value = new PLAIDKey(Config.LENGTH_RSA_KEY_BITS, Config.LENGTH_AES_KEY_BITS);
        } else {
			value = KeyBuilder.buildKey(type, length, false);        		        
        }
        
      }
    
    public short getHeader(byte[] buffer, short offset) {
    	    	
    	// Set the type byte
    	buffer[offset++] = value.getType();
    	
    	// Write the header
	    Util.arrayCopyNonAtomic(header, (short)0, buffer, offset, LENGTH_HEADER);
	    
	    // Include the type byte in the response length
	    return (short)(LENGTH_HEADER + 1);
	    
    }
    
    public void clearRecord() {
	    value.clearKey();	    
	    Util.arrayFillNonAtomic(header, (short)0, LENGTH_HEADER, (byte)0);
    }
    
	public void setRecord(byte[] buffer, short offset, short length, byte element) {
		
		/*
		 * HEADER
		 *
		 * NOTE:
		 * To support multi-APDU LOAD KEY commands, we always check if the header has been populated
		 * and if so, we confirm that the contents of existing and supplied headers match.
		 *
		 */
		
		// Are we already set ?
		if (getId() != 0) {
			// Check that the key header is a match
			if (Util.arrayCompare(buffer, offset, header, (short)0, LENGTH_HEADER) != 0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		} else {
			// Set the common header
			Util.arrayCopyNonAtomic(buffer, offset, header, (short)0, LENGTH_HEADER);        			
		}
		
		// Move past the header
		offset += LENGTH_HEADER;
		length -= LENGTH_HEADER;
		
		// Call the appropriate record method
		switch(value.getType()) {
			
		case PLAIDKey.TYPE_PLAID:
			setRecordTYPE_PLAID(buffer, offset, length, element);
			break;

		default:
			// This should never be reached and indicates that the applet constructor is generating keys of an unsupported type
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			break;
		}
	}
	
	private void setRecordTYPE_PLAID(byte[] buffer, short offset, short length, byte element) {

		// Cast to our known Key implementation
		PLAIDKey k = (PLAIDKey)value;
		
		// Set the appropriate element
		switch (element) {
			
		case PLAIDKey.ELEMENT_IAKEY_P:
			k.iaKeyPrivate.setP(buffer, offset, length);				
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_Q:
			k.iaKeyPrivate.setQ(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_PQ:
			k.iaKeyPrivate.setPQ(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_DP:
			k.iaKeyPrivate.setDP1(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_DQ:
			k.iaKeyPrivate.setDQ1(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_MODULUS:
			k.iaKeyPublic.setModulus(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_IAKEY_EXPONENT:
			k.iaKeyPublic.setExponent(buffer, offset, length);
			break;
			
		case PLAIDKey.ELEMENT_FAKEY:
			k.faKey.setKey(buffer, offset);
			break;
			
		default:
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			break;
		}
	}
	
    /*
     * Key header helper methods     
     */

    public short getId() {
        return Util.getShort(header, OFFSET_ID);
    }

    public byte getVersion() {
        return header[OFFSET_VERSION];
    }    

    public boolean getAttrPlaidAuth() {
    	short attr = Util.getShort(header, OFFSET_KEY_ATTR);
        return ( (attr & ATTR_PLAID_AUTH) != 0x00 );
    }
    
    public boolean getAttrPlaidKEK() {
    	short attr = Util.getShort(header, OFFSET_KEY_ATTR);
        return ( (attr & ATTR_PLAID_KEK) != 0x00 );
    }
    
}

