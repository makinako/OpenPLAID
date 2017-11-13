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
#endregion

#region "Class definitions"
namespace CardFramework.Protocols.Iso7816
{

    /*
     * ISO 7816-4 - Command Set
     */
    public enum Part4Instruction : byte
    {
        ActivateFile = 0x44,
        AppendRecord = 0xE2,
        ChangeReferenceData = 0x24,
        CreateFile = 0xE0,
        DeactivateFile = 0x04,
        DeleteFile = 0xE4,
        DisableVerificationRequirement = 0x26,
        EnableVerificationRequirement = 0x28,
        Envelope1 = 0xC2,
        Envelope2 = 0xC3,
        EraseBinary1 = 0x0E,
        EraseBinary2 = 0x0F,
        EraseRecords = 0x0C,
        ExternalAuthenticate = 0x82,
        GeneralAuthenticate1 = 0x86,
        GeneralAuthenticate2 = 0x87,
        GenerateAssymetricKeyPair = 0x46,
        GetChallenge = 0x84,
        GetDataA = 0xCA,
        GetDataB = 0xCB,
        GetResponse = 0xC0,
        InternalAuthenticate = 0x88,

        // ...

        Select = 0xA4
    }

    /*
     * ISO 7816-4 - P1 - SELECT FILE Command
     */
    public enum SelectMode
    {
        MfDfEf = 0x00,
        ChildDf = 0x01,
        EfUnderDf = 0x02,
        ParentDf = 0x03,
        DfName = 0x04,
        PathFromMf = 0x08,
        PathFromDf = 0x09
    }

    public enum SelectOccurrence
    {
        // File occurrence
        First = 0x00,
        Last = 0x01,
        Next = 0x02,
        Previous = 0x03,
    }

    public enum SelectFileControlInfo
    {
        // File Control Information
        Fci = 0x00,
        Fcp = 0x04,
        Fmd = 0x08,
        NoResponse = 0x0C
    }


    public class CApdu
    {
        #region "Members - Public"

        /// <summary>
        /// Initializes a new instance of the CAPDU class.
        /// </summary>
        public CApdu()
        {
            Data = new byte[0];
        }


        /// <summary>
        /// Initializes a new instance of the CAPDU class.
        /// </summary>
        public CApdu(byte cla, byte ins = 0, byte p1 = 0, byte p2 = 0, byte[] data = null, byte? le = null)
        {
            Cla = cla;
            Ins = ins;
            P1 = p1;
            P2 = p2;

            if (data == null)
            {
                Data = new byte[0];
            }
            else
            {
                Data = data;
            }

            LE = le;

        }

        public byte Cla { get; set; }
        public byte Ins { get; set; }
        public byte P1 { get; set; }
        public byte P2 { get; set; }
        public byte[] Data { get; set; }
        public byte? LE { get; set; }

        /// <summary>
        /// Returns this C-APDU instance in the form of a byte array.
        /// </summary>
        /// <returns>The byte array.</returns>
        public byte[] ToArray()
        {
            MemoryStream myStream = new MemoryStream();

            // CLA
            myStream.WriteByte(Cla);

            // INS
            myStream.WriteByte(Ins);

            // P1 & P2
            myStream.WriteByte(P1);
            myStream.WriteByte(P2);

            // Data
            if (Data?.Length != 0)
            {
                // Any frames above 255 bytes need to be sent as extended APDU
                if (Data.Length > 255)
                {
                    // Extended APDU
                    myStream.WriteByte(0x00);
                    myStream.WriteByte((byte)((Data.Length >> 8) & 0xFF));
                    myStream.WriteByte((byte)((Data.Length >> 0) & 0xFF));

                    // Data
                    myStream.Write(Data, 0, Data.Length);

                    // LE byte must match
                    if (LE != null)
                    {
                        myStream.WriteByte((byte)((LE >> 8) & 0xFF));
                        myStream.WriteByte((byte)((LE >> 0) & 0xFF));
                    }
                }
                else
                {
                    // Single byte APDU
                    myStream.WriteByte((byte)Data.Length);

                    // Data
                    myStream.Write(Data, 0, Data.Length);

                    // Le
                    if (LE != null) myStream.WriteByte(LE.Value);
                }
            }
            else
            {
                // Le
                if (LE != null) myStream.WriteByte(LE.Value);
            }


            // Finished
            return myStream.ToArray();
        }

        public override string ToString()
        {
            StringBuilder capdu = new StringBuilder();

            foreach (byte b in ToArray())
            {
                capdu.Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", b));
            }

            return capdu.ToString();
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        public const byte ClaProprietary = 0xFF;

        #endregion
    }
}
#endregion