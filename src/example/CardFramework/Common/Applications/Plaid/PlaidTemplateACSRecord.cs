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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Asn1;
using CardFramework.Helpers;
using System.Xml.Serialization;

namespace CardFramework.Applications.Plaid
{
    [XmlType("ACSRecord")]
    public class PlaidTemplateACSRecord
    {
        public const int LENGTH_OPMODE = 2;

        // The SAM key identifier
        [XmlAttribute(@"op_mode_id", DataType = "hexBinary")]
        public byte[] OpModeIdBytes;

        [XmlIgnore]
        public short OpModeId
        {
            get
            {
                short value = (short)(OpModeIdBytes[0] << 8);
                value |= (short)(OpModeIdBytes[1]);
                return value;
            }
        }

        // The default data value (needs to be either an expanded variable or hex binary)
        [XmlAttribute(@"data")]
        public string Data = null;

        public byte[] DataToArray()
        {
            if (string.IsNullOrEmpty(Data)) return null;
            if (!Data.IsHex()) throw new FormatException();
            return Data.HexToArray();
        }

        /// <summary>
        /// Checks to see if the data in this record has been supplied with a template parameter
        /// </summary>
        /// <returns></returns>
        public bool IsTemplate()
        {
            if (Data == null) return false;
            return (Data.StartsWith("$") && Data.EndsWith("$"));
        }

    }
}
