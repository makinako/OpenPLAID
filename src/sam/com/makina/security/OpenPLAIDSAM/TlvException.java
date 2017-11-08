package com.makina.security.OpenPLAIDSAM;

import javacard.framework.CardRuntimeException;

public class TlvException extends CardRuntimeException
{
  // Static instance for the singleton pattern
  private static TlvException instance = null;


  private TlvException(short reason)
  {
      super(reason);
  }

  // Static method to return the singleton instance
  public static TlvException getInstance(short reason)
  {
    if (instance == null)
    {
      instance = new TlvException(reason);
    }
    else
    {
      instance.setReason(reason);
    }

    return instance;
  }

  public static final short TAG_NOT_FOUND = (short)0x5000;  
  public static final short TAG_NUMBER_EXCEEDS_MAX = (short)0x5001;
  public static final short TAG_LENGTH_EXCEEDS_MAX = (short)0x5002;
  public static final short INVALID_LENGTH = (short)0x5003;
  public static final short INVALID_DATA = (short)0x5074;
}