package com.makina.security.OpenPLAIDSAM;

import javacard.framework.*;
import javacard.security.*;

public class PLAIDKey implements Key {
	
	public static final byte TYPE_PLAID = (byte)0x90;

	// PLAID key elements	
	public static final byte ELEMENT_IAKEY_P		= (byte)0;
	public static final byte ELEMENT_IAKEY_Q		= (byte)1;
	public static final byte ELEMENT_IAKEY_PQ		= (byte)2;
	public static final byte ELEMENT_IAKEY_DP		= (byte)3;
	public static final byte ELEMENT_IAKEY_DQ		= (byte)4;
	public static final byte ELEMENT_IAKEY_MODULUS	= (byte)5;
	public static final byte ELEMENT_IAKEY_EXPONENT	= (byte)6;	
	public static final byte ELEMENT_FAKEY			= (byte)7;	
	
	public RSAPrivateCrtKey iaKeyPrivate;
	public RSAPublicKey iaKeyPublic;
	public AESKey faKey;

	public PLAIDKey(short iaKeyLen, short faKeyLen) {		
		iaKeyPrivate = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, iaKeyLen, false);
		iaKeyPublic = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, iaKeyLen, false);
		faKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, faKeyLen, false);			
	}
	
	public void clearKey() {
		JCSystem.beginTransaction();
		
		iaKeyPrivate.clearKey();
		iaKeyPublic.clearKey();
		faKey.clearKey();
					
		JCSystem.commitTransaction();
	}
	
	public short getSize() {
		// NOTE: No use returning anything here as this is a hybrid key type.
		return (short)0;
	}
	
	public byte getType() {
		return TYPE_PLAID;
	}

	public boolean isInitialized() {
		
		// All three keys must be initialised
		return (iaKeyPrivate.isInitialized() && 
				iaKeyPublic.isInitialized() &&
				faKey.isInitialized());
	}
	
}
