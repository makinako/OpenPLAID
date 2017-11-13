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
using CardFramework.Protocols.Iso7816;

namespace CardFramework.Readers.PCSC
{
    public enum GeneralAuthenticateKeyType
    {
        KeyA = 0x60,
        KeyB = 0x61
    }

    [Flags]
    public enum OptionalLoadKeyStructure
    {
        CardKey = 0x00,
        ReaderKey = 0x80,

        PlainTransmission = 0x00,
        SecuredTransmission = 0x40,

        Volatile = 0x00,
        NonVolatile = 0x20
    }

    /// <summary>
    /// This class contains the optional 'storage card' commands as per PCSC v2.01.09 - 3.2.
    /// </summary>
    public class PCSCOptionalCommands
    {
        public const byte CLA = 0xFF;

        public const byte P1GetUID = 0x00;
        public const byte P1GetATS = 0x01;

        public const byte INSGetUID = 0xCA;
        public const byte INSGetATS = 0xCA;
        public const byte INSLoadKeys = 0x82;
        public const byte INSGeneralAuthenticate = 0x86;
        public const byte INSReadBinary = 0xB0;
        public const byte INSUpdateBinary = 0xD6;

        internal PCSCOptionalCommands(PCSCIso7816Protocol protocol)
        {
            myProtocol = protocol;
        }

        public byte[] ReadBinary(ushort address, byte length)
        {
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSReadBinary;
            command.P1 = (byte)(address >> 8);
            command.P2 = (byte)(address & 0xFF);
            command.LE = length; // 16 byte read

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("ReadBinary");
            }

            return response.Data;
        }

        public void UpdateBinary(ushort address, byte[] data)
        {
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSUpdateBinary;
            command.P1 = (byte)(address >> 8);
            command.P2 = (byte)(address & 0xFF);
            command.Data = data;

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("UpdateBinary");
            }
        }

        public void LoadKeys(OptionalLoadKeyStructure structure, byte secureKeyIndex, byte keyIndex, byte[] key)
        {
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSLoadKeys;
            command.P1 = (byte)((byte)structure | secureKeyIndex);
            command.P2 = keyIndex;
            command.Data = key;

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("LoadKeys");
            }
        }



        public void GeneralAuthenticate(ushort address, GeneralAuthenticateKeyType keyType, byte keyIndex)
        {
            const int AuthenticateDataLen = 5;

            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSGeneralAuthenticate;
            command.P1 = 0x00; // Always null
            command.P2 = 0x00; // Always null

            byte[] data = new byte[AuthenticateDataLen];
            data[0] = 0x01; // Static version
            data[1] = (byte)(address >> 8);
            data[2] = (byte)(address & 0xFF);
            data[3] = (byte)keyType;
            data[4] = 0;

            command.Data = data;

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GeneralAuthenticate");
            }
        }

        public byte[] GetUID()
        {
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSGetUID;
            command.P1 = P1GetUID;
            command.P2 = 0x00; // Always null

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GetUID");
            }

            return response.Data;
        }

        public byte[] GetATS()
        {
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INSGetATS;
            command.P1 = P1GetATS;
            command.P2 = 0x00; // Always null

            RApdu response = myProtocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GetATS");
            }

            return response.Data;
        }

        public void Verify()
        {
            throw new NotImplementedException();
        }

        private PCSCIso7816Protocol myProtocol;
    }
}
