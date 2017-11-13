﻿#region "Copyright"
/******************************************************************************************
 Copyright (C) 2012 Kim O'Sullivan (kim@makina.com.au)

 Permission is hereby granted, free of charge, to any person obtaining a copy of 
 this software and associated documentation files (the "Software"), to deal in the 
 Software without restriction, including without limitation the rights to use, copy, 
 modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 and to permit persons to whom the Software is furnished to do so, subject to the 
 following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies 
 or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT 
 OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************************/
#endregion

#region "Namespace definitions"
using System;
using System.Collections.Generic;
using System.Text;
using CardFramework.Protocols.Iso14443A;
using CardFramework.Protocols.Iso7816;
using CardFramework.Helpers;
#endregion

#region "Class definitions"
namespace CardFramework.Readers.PCSC
{

    public class PCSCIso14443AProtocol : PCSCIso7816Protocol
    {
        public byte[] UID { get; private set; }

        internal PCSCIso14443AProtocol(byte[] atr, PCSCCard card)
          : base(atr, card)
        {
            try
            {
                // Retrieve our UID
                CApdu command = new CApdu(0xFF, 0xCA, 0, le: 00);
                RApdu response = Transceive(command);
                if (response.IsError) throw new InvalidOperationException("Error retrieving the Card UID");
                UID = response.Data;
            }
            catch (Exception)
            {
                // Some IFD's don't support UID retrieval
            }
        }

        public override string ToString()
        {
            return @"ISO 7816 over ISO 14443-4 Protocol (ATR: " + Atr.ToString() + ")";
        }
    }
}
#endregion