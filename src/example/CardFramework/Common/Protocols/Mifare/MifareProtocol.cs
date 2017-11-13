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

namespace CardFramework.Protocols.Mifare
{
    public abstract class MifareProtocol : Protocol
    {
        protected MifareProtocol()
        {

        }

        public abstract byte[] ReadBlock(byte block);
        public abstract void WriteBlock(byte block, byte[] data);
        public abstract void Decrement(byte block, int value);
        public abstract void Increment(byte block, int value);
        public abstract void Restore(byte block);
        public abstract void Transfer(byte block);
        public abstract void Authenticate(byte sector, MifareKeyType keyType, byte[] key);

        public static byte GetSectorTrailerBlock(byte sector)
        {
            byte blockNo;

            // Calculate the appropriate block number
            if (sector >= 32)
            {
                // First calculate the blockNo for the maximum 4-block sector
                blockNo = 128;

                // Next, calculate the blockNo for each 16-block sector above 31
                blockNo += (byte)((sector - 32) * 16 + 15);
            }
            else
            {
                blockNo = (byte)(sector * 4 + 3);
            }

            return blockNo;
        }

        public void WritePermissions(byte sector, SectorPermissions permissions)
        {
            byte[] buffer = new byte[BlockLength];

            // Copy first 6 bytes (key A)
            Array.Copy(permissions.KeyA, 0, buffer, 0, 6);

            // Set access conditions
            byte block0 = (byte)permissions.Block0;
            byte block1 = (byte)permissions.Block1;
            byte block2 = (byte)permissions.Block2;
            byte block3 = (byte)permissions.SectorTrailer;

            // Byte 6
            buffer[6] = 0;
            buffer[6] |= (byte)(((block0 & C1) != 0x00) ? 0x00 : 0x01); // Inverted
            buffer[6] |= (byte)(((block1 & C1) != 0x00) ? 0x00 : 0x02); // Inverted
            buffer[6] |= (byte)(((block2 & C1) != 0x00) ? 0x00 : 0x04); // Inverted
            buffer[6] |= (byte)(((block3 & C1) != 0x00) ? 0x00 : 0x08); // Inverted
            buffer[6] |= (byte)(((block0 & C2) != 0x00) ? 0x00 : 0x10); // Inverted
            buffer[6] |= (byte)(((block1 & C2) != 0x00) ? 0x00 : 0x20); // Inverted
            buffer[6] |= (byte)(((block2 & C2) != 0x00) ? 0x00 : 0x40); // Inverted
            buffer[6] |= (byte)(((block3 & C2) != 0x00) ? 0x00 : 0x80); // Inverted

            // Byte 7
            buffer[7] = 0;
            buffer[7] |= (byte)(((block0 & C3) != 0x00) ? 0x00 : 0x01); // Inverted
            buffer[7] |= (byte)(((block1 & C3) != 0x00) ? 0x00 : 0x02); // Inverted
            buffer[7] |= (byte)(((block2 & C3) != 0x00) ? 0x00 : 0x04); // Inverted
            buffer[7] |= (byte)(((block3 & C3) != 0x00) ? 0x00 : 0x08); // Inverted
            buffer[7] |= (byte)(((block0 & C1) != 0x00) ? 0x10 : 0x00);
            buffer[7] |= (byte)(((block1 & C1) != 0x00) ? 0x20 : 0x00);
            buffer[7] |= (byte)(((block2 & C1) != 0x00) ? 0x40 : 0x00);
            buffer[7] |= (byte)(((block3 & C1) != 0x00) ? 0x80 : 0x00);

            // Byte 8
            buffer[8] = 0;
            buffer[8] |= (byte)(((block0 & C2) != 0x00) ? 0x01 : 0x00);
            buffer[8] |= (byte)(((block1 & C2) != 0x00) ? 0x02 : 0x00);
            buffer[8] |= (byte)(((block2 & C2) != 0x00) ? 0x04 : 0x00);
            buffer[8] |= (byte)(((block3 & C2) != 0x00) ? 0x08 : 0x00);
            buffer[8] |= (byte)(((block0 & C3) != 0x00) ? 0x10 : 0x00);
            buffer[8] |= (byte)(((block1 & C3) != 0x00) ? 0x20 : 0x00);
            buffer[8] |= (byte)(((block2 & C3) != 0x00) ? 0x40 : 0x00);
            buffer[8] |= (byte)(((block3 & C3) != 0x00) ? 0x80 : 0x00);

            // Byte 9 - User data
            buffer[9] = permissions.UserData;

            // Copy last 6 bytes (key B)
            Array.Copy(permissions.KeyB, 0, buffer, 10, 6);

            // Write permissions to the card
            WriteBlock(GetSectorTrailerBlock(sector), buffer);
        }

        /// <summary>
        /// The number of bytes per block
        /// </summary>
        public const int BlockLength = 16;

        /// <summary>
        /// The number of sectors on a 1K card
        /// </summary>
        public const int SectorCount1K = 16;

        /// <summary>
        /// The number of sectors on a 4K card
        /// </summary>
        public const int SectorCount4K = 40;

        /// <summary>
        /// The number of bytes used for a key, NOT the number of bits.
        /// </summary>
        public const int KeyLength = 6;

        /// <summary>
        /// The default key value used for a Mifare card in its factory state
        /// </summary>
        public static readonly byte[] FactoryKey = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        /// <summary>
        /// The position of the C1 flag in the access control permissions
        /// </summary>
        public const byte C1 = 0x01;

        /// <summary>
        /// The position of the C2 flag in the access control permissions
        /// </summary>
        public const byte C2 = 0x02;

        /// <summary>
        /// The position of the C2 flag in the access control permissions
        /// </summary>
        public const byte C3 = 0x04;
    }


    public class SectorPermissions
    {
        public byte[] KeyA { get; set; }
        public byte[] KeyB { get; set; }
        public AccessCondition Block0 { get; set; }
        public AccessCondition Block1 { get; set; }
        public AccessCondition Block2 { get; set; }
        public AccessCondition SectorTrailer { get; set; }
        public byte UserData;
    }

    public enum MifareKeyType
    {
        KeyA = 0x60,
        KeyB = 0x61
    }

    /// <summary>
    /// The preset access condition modes for the Mifare 1K/4K
    /// </summary>
    /// <remarks>
    /// Please refer to the datasheets of the Mifare 1K/4K for a detailed
    /// description of the meaning of these access conditions.
    /// </remarks>
    public enum AccessCondition
    {
        Mode0 = 0x00,
        Mode1 = 0x02,
        Mode2 = 0x01,
        Mode3 = 0x03,
        Mode4 = 0x04,
        Mode5 = 0x06,
        Mode6 = 0x05,
        Mode7 = 0x07
    }
}
