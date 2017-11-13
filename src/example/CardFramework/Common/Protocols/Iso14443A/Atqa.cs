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
using System.Xml.Serialization;
#endregion

#region "Class definitions"
namespace CardFramework.Protocols.Iso14443A
{
    public class Atqa
    {
        #region "Members - Public"

        public Atqa(byte[] atqa)
        {
            Value = atqa;
        }

        [XmlArray()]
        public byte[] Value { get; private set; }

        public Byte Coding
        {
            get
            {
                return (byte)(Value[1] & 0x0F);
            }
        }

        public Byte UidSize
        {
            get
            {
                switch (Value[0] & 0xC0)
                {
                    case 0x00: // Cascade level 1
                        return 4;

                    case 0x40: // Cascade level 2
                        return 7;

                    case 0x80: // Cascade level 3
                        return 10;

                    default:
                        return 0;
                }
            }
        }

        public bool Collision
        {
            get
            {
                return (0x00 != (Value[0] & 0x1F));
            }
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"
        #endregion
    }
}
#endregion