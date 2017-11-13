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
using System.IO;
using System.Globalization;
using CardFramework.Applications.Iso7816;
#endregion

#region "Class definitions"
namespace CardFramework.Protocols.Iso7816
{
    public class RApdu
    {
        #region "Members - Public"

        static RApdu()
        {
        }

        /// <summary>
        /// Initializes a new instance of the RAPDU class.
        /// </summary>
        public RApdu()
        {
        }

        public static RApdu Parse(byte[] apdu)
        {
            RApdu result = new RApdu();

            if (apdu.Length < 2)
            {
                throw new ArgumentException(@"Invalid R-APDU length", @"apdu");
            }

            // Parse SW2/1 & Data
            result.SW1 = apdu[apdu.Length - 2];
            result.SW2 = apdu[apdu.Length - 1];

            if (apdu.Length > 2)
            {
                result.Data = new byte[apdu.Length - 2];
                Array.Copy(apdu, result.Data, result.Data.Length);
            }
            else
            {
                result.Data = new byte[0];
            }

            return result;
        }

        /// <summary>
        /// Initializes a new instance of the RAPDU class.
        /// </summary>
        /// <param name="SW1">The SW1 flag.</param>
        /// <param name="SW2">The SW2.</param>
        public RApdu(byte sw1, byte sw2)
        {
            Data = new byte[0];
            SW1 = sw1;
            SW2 = sw2;
        }

        public byte SW1 { get; set; }
        public byte SW2 { get; set; }

        public ushort SW12
        {
            get
            {
                return (ushort)(((ushort)SW1 << 8) | (ushort)SW2);

            }
        }

        public byte[] Data { get; set; }

        /// <summary>
        /// Returns this R-APDU instance in the form of a byte array.
        /// </summary>
        /// <returns>The array.</returns>
        public byte[] ToArray()
        {
            MemoryStream stream = new MemoryStream(Data.Length + 2);

            stream.Write(Data, 0, Data.Length);
            stream.WriteByte(SW1);
            stream.WriteByte(SW2);

            return stream.ToArray();
        }

        public override string ToString()
        {
            StringBuilder rapdu = new StringBuilder();

            foreach (byte b in Data)
            {
                rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", b));
            }
            rapdu.Append(" ");
            rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", SW1));
            rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", SW2));

            return rapdu.ToString();
        }

        public string ToString(bool status)
        {
            StringBuilder rapdu = new StringBuilder();

            foreach (byte b in Data)
            {
                rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", b));
            }
            if (status)
            {
                rapdu.Append(" ");
                rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", SW1));
                rapdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", SW2));
            }

            return rapdu.ToString();
        }

        /// <summary>
        /// Gets a value indicating whether this instance is an error.
        /// </summary>
        /// <value><c>true</c> if this instance is an error; otherwise, <c>false</c>.</value>
        public bool IsError
        {
            get
            {
                return !(0x90 == (SW1 & 0x90));
            }
        }

        public Exception ThrowBySW(string source)
        {
            return new Iso7816Exception(SW12, source);
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        public const byte SW1Ok = 0x90;
        public const byte SW1MoreData = 0x61;
        public const byte SW1FormatError = 0x62;

        #endregion
    }
}
#endregion