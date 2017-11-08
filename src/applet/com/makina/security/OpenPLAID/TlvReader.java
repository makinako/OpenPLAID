package com.makina.security.OpenPLAID;

import javacard.framework.*;

public class TlvReader {

	/*
	 * CONSTANTS
	 */
	 
	// Tag Class
	public static final byte TLV_CLASS_UNIVERSAL 		= (byte)0x00;
	public static final byte TLV_CLASS_APPLICATION 		= (byte)0x01;
	public static final byte TLV_CLASS_CONTEXT 			= (byte)0x02;
	public static final byte TLV_CLASS_PRIVATE 			= (byte)0x03;

	// Masks
	public static final byte MASK_CONSTRUCTED 			= (byte) 0x20;
	public static final byte MASK_LOW_TAG_NUMBER 		= (byte) 0x1F;
	public static final byte MASK_HIGH_TAG_NUMBER 		= (byte) 0x7F;
	public static final byte MASK_HIGH_TAG_MOREDATA 	= (byte) 0x80;
	public static final byte MASK_LONG_LENGTH 			= (byte) 0x80;
	public static final byte MASK_LENGTH 				= (byte) 0x7F;

	// Universal tags
	public static final byte ASN1_INTEGER 		= (byte)0x02;
	public static final byte ASN1_BIT_STRING 	= (byte)0x03;
	public static final byte ASN1_OCTET_STRING 	= (byte)0x04;
	public static final byte ASN1_NULL 			= (byte)0x05;
	public static final byte ASN1_OBJECT 		= (byte)0x06;
	public static final byte ASN1_ENUMERATED	= (byte)0x0A;
	public static final byte ASN1_SEQUENCE 		= (byte)0x10; //  "Sequence" and "Sequence of"
	public static final byte ASN1_SET 			= (byte)0x11; //  "Set" and "Set of"
	public static final byte ASN1_PRINT_STRING 	= (byte)0x13;
	public static final byte ASN1_T61_STRING 	= (byte)0x14;
	public static final byte ASN1_IA5_STRING 	= (byte)0x16;
	public static final byte ASN1_UTC_TIME 		= (byte)0x17;
	
	public static final byte TAG_NOT_FOUND		= (byte)-1;
	
	public static short find(byte[] data, short offset, byte tag)
	{
		try {
			while (offset < data.length)
			{	
				//
				// HACK: data.length is not an accurate representation of the end of the ASN packet, 
				// so until we are able to locally store the actual length, we abort on the special tag value
				// of zero (0). This means that the caller needs to make sure they have zeroe'd the buffer
				// after their ASN1 data object before calling.
				//			
				if ((byte)0 == getTagNumber(data, offset)) {
					return TAG_NOT_FOUND;
				}
				
				// Is this our tag number?
				if (tag == getTagNumber(data, offset)) {
					// We've found it!
					return offset;
				}

				// Is this a constructed object?
				if (getIsConstructed(data, offset))
				{
					// Skip to the first child element
					offset = getDataOffset(data, offset);
				}
				else
				{
					// Skip to the next
					short tagLength = getLength(data, offset);
					offset = getDataOffset(data, offset);
					offset += tagLength;
				}
			}
				
			// We didn't find the requested tag;
			return TAG_NOT_FOUND;
			
		} catch (Exception ex) {
			return TAG_NOT_FOUND;
		}
	}

	public static short findNext(byte[] data, short offset, byte tag)
	{
		try {
		  // First move to the next object
		  // Is this a constructed object?
		  if (getIsConstructed(data, offset)) {
			// Skip to the first child element
			offset = getDataOffset(data, offset);
		  }
		  else {
			// Skip to the next
			short tagLength = getLength(data, offset);
			offset = getDataOffset(data, offset);
			offset += tagLength;
		  }

		  // Now find as normal
		  return find(data, offset, tag);
		} catch (Exception ex) {
			return TAG_NOT_FOUND;
		}		
	}
	

	/*
	 * Returns whether the TLV data element at the current position is
	 * constructed or not (primitive).
	 */
	public static boolean getIsConstructed(byte[] data, short offset)
	{
	  // Check bit 6 of the T element
	  return ((data[offset] & MASK_CONSTRUCTED) != 0);
	}
	/*
	 * Returns the tag number for the TLV data element at the current position.
	 * NOTE: This does NOT include the class and/or constructed flag. NOTE: This
	 * only supports tag values up to 127.
	 */
	public static byte getTagNumber(byte[] data, short offset)
	{
	  if ((data[offset] & MASK_LOW_TAG_NUMBER) != MASK_LOW_TAG_NUMBER)
	  {
		// This is a low-tag-number form (Tags 0 to 31)
		return (byte)(data[offset] & MASK_LOW_TAG_NUMBER);
	  }
	  else
	  {
		// This is a high-tag-number form (Tags 31+)
		offset++;
		if ((data[offset] & MASK_HIGH_TAG_MOREDATA)
				== MASK_HIGH_TAG_MOREDATA)
		{
		  // This implementation does not support tags > 127
		  TlvException.throwIt(TlvException.TAG_NUMBER_EXCEEDS_MAX);
		  return (byte)0; // Dummy
		}
		else
		{
		  return (byte)(data[offset] & MASK_HIGH_TAG_NUMBER);
		}
	  }
	}

	public static short getLength(byte[] data, short offset)
	{
	  // First, skip through the T element
	  if ((data[offset++] & MASK_LOW_TAG_NUMBER) == MASK_LOW_TAG_NUMBER)
	  {
		// This is a high-tag-number form (Tags 31+)
		if ((data[offset++] & MASK_HIGH_TAG_MOREDATA)
				== MASK_HIGH_TAG_MOREDATA)
		{
		  // This implementation does not support tags > 127
		  TlvException.throwIt(TlvException.TAG_NUMBER_EXCEEDS_MAX);
		}
	  }

	  // Is this a long-form length byte?
	  if ((data[offset] & MASK_LONG_LENGTH) == MASK_LONG_LENGTH)
	  {
		// Is there more than 1 byte?
		if ((data[offset] & MASK_LENGTH) == 1)
		{
			// Values 0-255
			offset++;
			return (short)(data[offset] & (short)0xFF);
		} else if ((data[offset] & MASK_LENGTH) == 2) {
			// Values 0-65535
			// NOTE: Since we're assigning to a short, we don't
			// support anything greater than +32766.
			offset++;
			return Util.getShort(data, offset);			
		} 
		else
		{
		  // We don't support multi-byte length definitions > 2
		  TlvException.throwIt(TlvException.TAG_LENGTH_EXCEEDS_MAX);
		  return (short)0; // Dummy for compiler
		}
	  } else {
		  // short-form length		  
		  return (short)(data[offset] & (short)0xFF);
	  }
	}

	public static byte getClass(byte[] data, short offset)
	{
	  return (byte)(data[offset] >> 6);
	}

	public static short getDataOffset(byte[] data, short offset)
	{
	  // First, skip through the T(ype) element
	  if ((data[offset++] & MASK_LOW_TAG_NUMBER) == MASK_LOW_TAG_NUMBER)
	  {
		// This is a high-tag-number form (Tags 31+)
		if ((data[offset++] & MASK_HIGH_TAG_MOREDATA) == MASK_HIGH_TAG_MOREDATA)
		{
		  // This implementation does not support tags > 127
		  TlvException.throwIt(TlvException.TAG_NUMBER_EXCEEDS_MAX);
		}
	  }

	  // Skip through the L(ength) element
	  
	  // Is this a long-form length byte?
	  if ((data[offset] & MASK_LONG_LENGTH) == MASK_LONG_LENGTH)
	  {
		  // Skip the additional length bytes
		  offset += (byte)(data[offset] & MASK_LENGTH);
	  }
	  offset++; // Skip the initial length byte

	  return offset;
	}

	public static short toShort(byte[] data, short offset)
	{
		short length = getLength(data, offset);
		
	    // Skip to the data value
	    offset = getDataOffset(data, offset);
		if ((short)1 == length) {
			return data[offset];
		} else if ((short)2 == length) {
			return Util.getShort(data, offset);
		} else {
			TlvException.throwIt(TlvException.TAG_LENGTH_EXCEEDS_MAX);
			return (short)0; // Dummy
		}
	}

	public static byte toByte(byte[] data, short offset)
	{
	  // Skip to the data value
	  offset = getDataOffset(data, offset);

	  return data[offset];
	}

}