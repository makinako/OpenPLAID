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
using CardFramework.Protocols.Iso7816;
using System.IO;
using System.ComponentModel;
#endregion

#region "Class definitions"
namespace CardFramework.Applications.Iso7816
{
    public class Iso7816Application : CardApplication
    {
        #region "Members - Public"

        public override bool Discover(Card card)
        {
            /*
             * TODO: What happens when using a non-pcsc contactless implementation that doesn't use an 
             * Iso7816 underlying protocol, but still uses T=CL with ISO-7816-4 commands?
             */
            return (card.HasProtocol<Iso7816Protocol>());
        }

        //public byte[] ReadBinary();
        //public void WriteBinary(byte[] data);
        //public void UpdateBinary();
        //public void EraseBinary();
        //public void ReadRecords();
        //public void WriteRecord();
        //public void AppendRecord();
        //public void UpdateRecord();
        //public void GetData();
        //public void PutData();

        public byte[] SelectFile(byte[] id, SelectMode mode)
        {
            return SelectFile(id, mode, SelectOccurrence.First, SelectFileControlInfo.Fci);
        }

        public byte[] SelectFile(byte[] id, SelectMode mode, SelectOccurrence occurrence, SelectFileControlInfo info)
        {
            if (id == null) throw new ArgumentException("id");

            // Setup the command
            CApdu command = new CApdu();
            command.Cla = 0x00;
            command.Ins = (byte)Part4Instruction.Select;
            command.P1 = (byte)mode;
            command.P2 = (byte)((byte)occurrence | (byte)info);
            command.Data = id;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test response
            if (response.IsError)
            {
                throw response.ThrowBySW("SelectFile");
            }

            return response.Data;
        }

        protected RApdu Transcieve(byte cla, byte ins, byte p1 = 0, byte p2 = 0, byte[] data = null, byte? le = 0)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = cla;
            command.Ins = ins;
            command.P1 = p1;
            command.P2 = p2;
            if (data != null) command.Data = data;
            if (le != null) command.LE = le;

            // Transceive
            RApdu response = Transcieve(command);
            return response;
        }

        protected RApdu Transcieve(CApdu command)
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();
            MemoryStream data = new MemoryStream();

            // Send the first (and possibly only) tranceive command
            RApdu response = protocol.Transceive(command);

            // Check for more data
            while (response.SW1 == RApdu.SW1MoreData)
            {
                // Dump what we have so far to the memory stream
                data.Write(response.Data, 0, response.Data.Length);

                // Issue a 'GET RESPONSE' request
                command.Ins = (byte)Part4Instruction.GetResponse;
                command.P1 = 0x00;
                command.P2 = 0x00;
                command.Data = new byte[0];
                command.LE = response.SW2;

                // Request the next block
                response = protocol.Transceive(command);
            }

            // Check for other error, just return if it is
            if (response.IsError) return response;

            // Get the final block of response data
            data.Write(response.Data, 0, response.Data.Length);

            // Done, return the last RApdu with the full data
            response.Data = data.ToArray();
            return response;
        }

        public byte[] GetDataExtended(byte[] id, byte p1, byte p2)
        {
            // Argument validation
            if (id == null) throw new ArgumentException("id");

            // Setup the command and transcieve
            CApdu command = new CApdu();
            command.Cla = 0x00;
            command.Ins = (byte)Part4Instruction.GetDataB;
            command.P1 = p1;
            command.P2 = p2;
            command.Data = id;
            command.LE = 0x00;

            RApdu response = Transcieve(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GetDataExtended");
            }

            return response.Data;
        }

        public byte[] GetData(byte[] id)
        {
            // Argument validation
            if (id == null) throw new ArgumentException("id");

            // Setup the command and transcieve
            CApdu command = new CApdu();
            command.Cla = 0x00;
            command.Ins = (byte)Part4Instruction.GetDataA;
            command.P1 = id[0];
            command.P2 = id[1];

            RApdu response = Transcieve(command);

            // Validate the response
            if (response.IsError)
            {
                throw response.ThrowBySW("GetData");
            }

            return response.Data;
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        public const byte GetDataP1CurrentDF = 0x3F;
        public const byte GetDataP2CurrentDF = 0xFF;

        #endregion
    }

}
#endregion
