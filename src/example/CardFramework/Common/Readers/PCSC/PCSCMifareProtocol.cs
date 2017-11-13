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
using CardFramework.Protocols.Mifare;

namespace CardFramework.Readers.PCSC
{
    public class PCSCMifareProtocol : MifareProtocol
    {
        private PCSCCard myCard;

        public PCSCMifareProtocol(PCSCCard card)
        {
            myCard = card;
        }

        public override byte[] ReadBlock(byte block)
        {
            return myCard.OptionalCommands.ReadBinary(block, MifareProtocol.BlockLength);
        }

        public override void WriteBlock(byte block, byte[] data)
        {
            myCard.OptionalCommands.UpdateBinary(block, data);
        }

        public override void Decrement(byte block, int value)
        {
            throw new NotImplementedException();
        }

        public override void Increment(byte block, int value)
        {
            throw new NotImplementedException();
        }

        public override void Restore(byte block)
        {
            throw new NotImplementedException();
        }

        public override void Transfer(byte block)
        {
            throw new NotImplementedException();
        }

        public override void Authenticate(byte sector, MifareKeyType keyType, byte[] key)
        {
            // Load the factory MIFARE key into volatile memory      
            myCard.OptionalCommands.LoadKeys(OptionalLoadKeyStructure.CardKey | OptionalLoadKeyStructure.Volatile,
                                            0,
                                            (byte)keyType,
                                            key);

            // Authenticate to the sector
            if (keyType == MifareKeyType.KeyA)
            {
                myCard.OptionalCommands.GeneralAuthenticate(MifareProtocol.GetSectorTrailerBlock(sector), GeneralAuthenticateKeyType.KeyA, (byte)keyType);
            }
            else
            {
                myCard.OptionalCommands.GeneralAuthenticate(MifareProtocol.GetSectorTrailerBlock(sector), GeneralAuthenticateKeyType.KeyB, (byte)keyType);
            }
        }

        public override void LoadDiscoveryData()
        {
            throw new NotImplementedException();
        }

        public override string DiscoverPlatform()
        {
            throw new NotImplementedException();
        }
    }
}
