#region "Copyright"
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
using CardFramework.Helpers;
#endregion

#region "Class definitions"
namespace CardFramework.Protocols.Iso7816
{
    public class Atr
    {
        #region "Members - Public"

        private Atr(byte[] atr)
        {
            Value = atr;
        }

        public byte[] Value { get; private set; }

        public override string ToString()
        {
            return Converters.ByteArrayToString(Value);
        }

        public static Atr Parse(byte[] data)
        {
            BinaryParser parser = new BinaryParser(data);

            // Perform a quick sanity check on the ATR, see ISO-7816-3 definition of 'TS' character.
            if (data[0] != 0x3F && data[0] != 0x3B)
            {
                throw new ProtocolException(@"Invalid ATR according to ISO 7816-3");
            }

            Atr atr = new Atr(data);
            return atr;
        }

        #endregion

        #region "Members - Private / Protected"

        #endregion

        #region "Constants / Private Declarations"

        #endregion
    }
}
#endregion