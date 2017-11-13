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
using System.Text;
using System.Globalization;

/*
    ANNEX D USE OF THE BASIC ENCODING RULES OF ASN.1

    D.1 BER-TLV data object

    Each BER-TLV data object (see ISO/IEC 8825) shall consist of 2 or 3
    consecutive fields :

    The tag field T consists of one or more consecutive bytes. It encodes a
    class, a type and a number.
    The length field consists of one or more consecutive bytes. It encodes
    an integer L.
    If L is not null, then the value field V consists of L consecutive bytes.
    If L is null, then the data object is empty: there is no value field.

    ISO/IEC 7816 uses neither '00' nor 'FF' as tag value.

    NOTE - Before, between or after BER-TLV data objects, '00' or 'FF' bytes
    without any meaning may occur (e.g. due to erased or modified TLV-coded
    data objects).

    D.2 Tag field

    The bits B8 and B7 of the leading byte of tag field shall encode the tag
    class, i.e. the class of the data object.

    B8-7='00' introduces a tag of universal class
    B8-7='01' introduces a tag of application class
    B8-7='10' introduces a tag of context-specific class
    B8-7='11' introduces a tag of private class

    The bit B6 of the leading byte of the tag field shall encode the tag type,
    i.e. the type of the data object.

    B6=0 introduces a primitive data object
    B6=1 introduces a constructed data object

    If the bits B5-B1 of the leading byte are not all set to 1, then they
    shall encode an integer equal to the tag number which therefore lies in the
    range from 0 to 30. Then the tag field consists of a single byte.

    Otherwise (B5-B1 set to 1 in the leading byte), the tag field shall
    continue on one or more shubsequent bytes.

    The bit B8 of each subsequent byte shall be set to 1, unless it is the
    last subsequent byte
    The bits B7-B1 of the first subsequent byte shall not be all set to 0
    The bits B7-B1 of the first subsequent byte, folowed by the bits B7 to B1
    of each further subsequent byte, up to and including the bits B7-B1 of
    the last subsequent byte, shall encode an integer equal to the tag
    number (thus strictly positive).

    D.3 Length field

    In short form, the length field consists of a single byte where the bit B8
    shall be set to 0 and the bits B7-B1 shall encode an integer equal to the
    number of bytes in the value field. Any length from 0-127 can thus be
    encoded by 1 byte.

    In long form, the length field consists of a leading byte where the bit B8
    shall be set to 1 and the B7-B1 shall not be all equal, thus encoding a
    positive integer equal to the number of subsequent bytes in the length
    field. Those subsequent bytes shall encode an integer equal to the number
    of bytes in the value field. Any length within the APDU limit (up to 65535)
    can thus be encoded by 3 bytes.

    NOTE - ISO/IEC 7816 does not use the indefinite lengths specified by the
    basic encoding rules of ASN.1 (see ISO/IEC 8825).

    D.4 Value field

    In this part of ISO/IEC 7816, the value field of some primitive BER-TLV
    data objects consists of zero, one or more SIMPLE-TLV data objects.

    The value field of any other primitive BER-TLV data object consists of
    zero, one or more data elements fixed by the specifications of the data
    objects.

    The value field of each constructed BER-TLV data object consists of zero,
    one or more BER-TLV data objects.
 */

namespace CardFramework.Formats
{
    public enum TlvTagClass
    {
        Invalid,
        Universal,
        Application,
        Context,
        Private
    }

    public enum TlvTagType
    {
        Primitive,
        Constructed
    }

    public class TlvPrimitive : TlvConstructed
    {
        [CLSCompliant(false)]
        public ushort ToUInt16()
        {
            ushort v = 0;
            v |= Value[0];
            v |= (ushort)(Value[1] << 8);
            return v;
        }

        public short ToInt16()
        {
            short v = 0;
            v |= (short)Value[0];
            v |= (short)(Value[1] << 8);
            return v;
        }

        public int ToInt32()
        {
            int v = 0;
            v |= Value[0];
            v |= (Value[1] << 8);
            v |= (Value[2] << 16);
            v |= (Value[3] << 24);
            return v;
        }

        [CLSCompliant(false)]
        public uint ToUInt32()
        {
            uint v = 0;
            v |= Value[0];
            v |= (uint)(Value[1] << 8);
            v |= (uint)(Value[2] << 16);
            v |= (uint)(Value[3] << 24);
            return v;
        }

        public byte ToByte()
        {
            return Value[0];
        }

        public override string ToString()
        {
            return Encoding.ASCII.GetString(Value, 0, Value.Length);
        }
    }

    public class TlvConstructed : TlvObject
    {
        /// <summary>
        /// Finds the specified tag.
        /// </summary>
        /// <param name="tag">The tag.</param>
        /// <returns></returns>
        public TlvObject Find(int tag)
        {
            int myIndex = 0;

            TlvObject myTLV = null;

            while (myIndex < Value.Length)
            {
                /*
                 * RETRIEVE THE TAG TYPE
                 * The bit B6 of the leading byte of the tag field shall encode the tag type,
                 * i.e. the type of the data object.
                 *
                 * B6=0 introduces a primitive data object
                 * B6=1 introduces a constructed data object
                 */
                if ((Value[myIndex] & 0x20) == 0x20)
                {
                    myTLV = new TlvConstructed();
                }
                else
                {
                    myTLV = new TlvPrimitive();
                }

                /*
                 * RETRIEVE THE TAG NUMBER
                 * 
                 * If the bits B5-B1 of the leading byte are not all set to 1, then may they
                 * shall encode an integer equal to the tag number which therefore lies in the
                 * range from 0 to 30. Then the tag field consists of a single byte.

                 * Otherwise (B5-B1 set to 1 in the leading byte), the tag field shall
                 * continue on one or more shubsequent bytes.

                 * The bit B8 of each subsequent byte shall be set to 1, unless it is the
                 * last subsequent byte
                 * The bits B7-B1 of the first subsequent byte shall not be all set to 0
                 * The bits B7-B1 of the first subsequent byte, folowed by the bits B7 to B1
                 * of each further subsequent byte, up to and including the bits B7-B1 of
                 * the last subsequent byte, shall encode an integer equal to the tag
                 * number (thus strictly positive).
                 */

                if (0x1F == (Value[myIndex] & 0x1F))
                {
                    // Set the first byte of the tag number
                    myTLV.Number = Value[myIndex];

                    while (true)
                    {
                        // Move to the next byte
                        myIndex++;

                        // Shift the number over by 8 bits
                        myTLV.Number <<= 8;

                        // Assign the next value to the lower byte
                        myTLV.Number |= Value[myIndex];

                        // If the MSB is clear then this is our last byte
                        if ((Value[myIndex] & 0x80) == 0x00) break;
                    }
                }
                else
                {
                    // This is a low-tag number
                    /*
                     * NOTE: When documentation refers to the tag number it also
                     * seems to include the class/type information so we won't trim
                     * it out here.
                     */
                    myTLV.Number = Value[myIndex];
                }

                // Move to the next byte
                myIndex++;

                /*
                 * LENGTH
                 */
                int myLength = 0;

                if (0x80 == (Value[myIndex] & 0x80))
                {
                    // This is a long length
                    int myLengthBytes = Value[myIndex] & 0x7F;

                    for (int i = 0; i < myLengthBytes; i++)
                    {
                        // Move to the next byte
                        myIndex++;

                        // Shift our length over by 8 bits
                        myLength <<= 8;

                        // Copy the value
                        myLength |= Value[myIndex];

                    }
                }
                else
                {
                    // This is a short length (msb is 0 here so we take the whole byte)
                    myLength = Value[myIndex];
                }

                // Move to the next byte
                myIndex++;

                // Is this the tag we're looking for?
                if (myTLV.Number == tag)
                {
                    // Set our tag value
                    myTLV.Value = new byte[myLength];
                    Array.Copy(Value, myIndex, myTLV.Value, 0, myLength);

                    // Finished!
                    return myTLV;
                }
                else
                {
                    // Move to the next tag
                    myIndex += myLength;
                }
            }

            // Nothing was found
            return null;
        }

    }

    public abstract class TlvObject
    {
        private byte[] myValue;
        private int myNumber;

        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Properties
        //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        #region Properties

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        public byte[] Value
        {
            get { return myValue; }
            set { myValue = value; }
        }

        /// <summary>
        /// Gets or sets the class.
        /// </summary>
        /// <value>The class.</value>
        public TlvTagClass Class
        {
            get
            {
                /*
                 * The bits B8 and B7 of the leading byte of tag field shall encode the tag
                 * class, i.e. the class of the data object.
                 * B8-7='00' introduces a tag of universal class
                 * B8-7='01' introduces a tag of application class
                 * B8-7='10' introduces a tag of context-specific class
                 * B8-7='11' introduces a tag of private class
                 */
                switch (myNumber & 0xC0)
                {
                    case 0x00: // Universal
                        return TlvTagClass.Universal;

                    case 0x40: // Application
                        return TlvTagClass.Application;

                    case 0x80: // Context-Specific
                        return TlvTagClass.Context;

                    case 0xC0: // Private
                        return TlvTagClass.Private;

                    default: // Error
                        return TlvTagClass.Invalid;
                }
            }
        }

        /// <summary>
        /// Gets or sets the length.
        /// </summary>
        /// <value>The length.</value>
        public int Length
        {
            get { return myValue.Length; }
        }

        /// <summary>
        /// Gets or sets the tag.
        /// </summary>
        /// <value>The tag.</value>
        public int Number
        {
            get { return myNumber; }
            set { myNumber = value; }
        }
        #endregion
    }

    public sealed class BerTlv
    {
        public static bool Exists(byte[] data, int tag)
        {
            return (Query(data, tag) != null);
        }
        public static bool Exists(byte[] data, string path)
        {
            return (Query(data, path) != null);
        }

        public static TlvObject Query(byte[] data, int tag)
        {
            /*
             * Search for the tag.
             */
            TlvConstructed myTag = new TlvConstructed();
            myTag.Value = data;
            return myTag.Find(tag);
        }

        public static TlvObject Query(byte[] data, string path)
        {
            /*
             * Transform the path into its separate tags and validate them.
             */
            List<int> myNumbers = new List<int>();

            foreach (string t in path.Split('/'))
            {
                try
                {
                    myNumbers.Add(Int32.Parse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                }
                catch
                {
                    throw new ArgumentException(@"Error parsing the BER path", @"path");
                }
            }

            TlvObject myTag = new TlvConstructed();
            myTag.Value = data;

            /*
             * Search recursively for the tag.
             */
            for (int i = 0; i < myNumbers.Count; i++)
            {
                myTag = ((TlvConstructed)myTag).Find(myNumbers[i]);

                if (null == myTag)
                {
                    // The path wasn't found
                    return null;
                }
            }

            // Return what we found
            return myTag;
        }

        public byte[] Data
        {
            get { return myData; }
            set { myData = value; }
        }

        private byte[] myData;
    }
}
