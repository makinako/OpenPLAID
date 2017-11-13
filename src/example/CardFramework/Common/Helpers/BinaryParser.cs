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
using System.IO;
using System.Net;

namespace CardFramework.Helpers
{
    public sealed class BinaryParser : IDisposable
    {
        private Stream myStream;

        public BinaryParser()
        {
            myStream = new MemoryStream();
        }

        public BinaryParser(Byte[] data)
        {
            myStream = new MemoryStream(data);
        }

        public BinaryParser(Stream stream)
        {
            myStream = stream;
        }

        public BinaryParser(ByteEndianess byteEndianess) : this()
        {
            myByteEndianess = byteEndianess;
        }

        public BinaryParser(ByteEndianess byteEndianess, BitEndianess bitEndianess) : this()
        {
            myByteEndianess = byteEndianess;
            myBitEndianess = bitEndianess;
        }

        public BinaryParser(Byte[] data, ByteEndianess byteEndianess, BitEndianess bitEndianess)
          : this(data)
        {
            myByteEndianess = byteEndianess;
            myBitEndianess = bitEndianess;
        }

        public BinaryParser(Byte[] data, ByteEndianess byteEndianess)
          : this(data)
        {
            myByteEndianess = byteEndianess;
        }

        public BinaryParser(Stream stream, ByteEndianess byteEndianess, BitEndianess bitEndianess) : this(stream)
        {
            myByteEndianess = byteEndianess;
            myBitEndianess = bitEndianess;
        }

        ~BinaryParser()
        {
            Dispose();
        }

        public long Position
        {
            get { return myStream.Position; }
            set { myStream.Position = value; }
        }

        public byte BitPosition
        {
            get { return myBitPosition; }
            set
            {
                if (value > 8)
                {
                    throw new ArgumentException("BitPosition");
                }
                else if (value == 8)
                {
                    // Move our stream forward
                    myStream.Position++;
                    myBitPosition = 0;
                }
                else
                {
                    myBitPosition = (byte)(value % 8);
                }
            }
        }

        public long Length
        {
            get { return myStream.Length; }
        }

        #region Read Methods

        // FIXME: If the BitPosition != 0 and we are on the last byte, it will crash!
        public long ReadUIntN(int bitLength)
        {
            long value = 0;

            if (bitLength > 64) throw new ArgumentException(@"Bit length must not exceed 64 bits", "bitLength");

            while (bitLength > 8)
            {
                // Shift the value over 8 bits
                value <<= 8;

                // Assign the lowest nibble
                value |= ReadUInt8();

                // Reduce the length to read
                bitLength -= 8;
            }

            // Just end it here if we've already gone through the values
            if (bitLength == 0) return value;

            // Shift the value over 8 bits
            value <<= 8;

            // Read the next value and mask off the lower n bits
            value += (long)(ReadUInt8() & (byte)(Math.Pow(2, bitLength) - 1));

            // Set the new bit offset so the ReadUInt8() method knows where to start
            myBitPosition += (byte)bitLength;

            // If we have not gone over the byte boundary yet, move back to the original position.
            if (myBitPosition < 8) myStream.Position--;

            myBitPosition %= 8; // Roll if >= 8

            // Done
            return value;
        }

        public Byte ReadUInt8()
        {
            int value = myStream.ReadByte();
            if (value < 0) throw new EndOfStreamException();

            byte result = (byte)value;

            // Are we reading from a non-zero bit offset?
            if (myBitPosition != 0)
            {
                // First, move the bits we want to keep to the top by shifting them by myBitPosition
                result <<= myBitPosition;

                // Read the next byte
                value = myStream.ReadByte();
                if (value < 0) throw new EndOfStreamException();

                // Move the stream pointer immediately back, since we are only reading a portion of this.
                myStream.Position--;

                // Right-shift (8 - myBitPosition) bits to move the first myBitPosition bits into the lower part
                value >>= (8 - myBitPosition);

                result |= (byte)value;
            }

            // Change bit-order if appropriate.
            if (BitEndianess.Lsb == myBitEndianess) result = Converters.SwapBitOrder(result);

            // Done
            return result;
        }

        [CLSCompliant(false)]
        public UInt16 ReadUInt16()
        {
            UInt16 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (UInt16)(ReadUInt8() << 8);
                value |= (UInt16)(ReadUInt8());
            }
            else
            {
                value = (UInt16)(ReadUInt8());
                value |= (UInt16)(ReadUInt8() << 8);
            }

            return value;
        }

        [CLSCompliant(false)]
        public UInt32 ReadUInt24()
        {
            UInt32 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value |= (UInt32)(ReadUInt8() << 16);
                value |= (UInt32)(ReadUInt8() << 8);
                value |= (UInt32)(ReadUInt8());
            }
            else
            {
                value = (UInt32)(ReadUInt8());
                value |= (UInt32)(ReadUInt8() << 8);
                value |= (UInt32)(ReadUInt8() << 16);
            }

            return value;
        }

        [CLSCompliant(false)]
        public UInt32 ReadUInt32()
        {
            UInt32 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (UInt32)(ReadUInt8() << 24);
                value |= (UInt32)(ReadUInt8() << 16);
                value |= (UInt32)(ReadUInt8() << 8);
                value |= (UInt32)(ReadUInt8());
            }
            else
            {
                value = (UInt32)(ReadUInt8());
                value |= (UInt32)(ReadUInt8() << 8);
                value |= (UInt32)(ReadUInt8() << 16);
                value |= (UInt32)(ReadUInt8() << 24);
            }

            return value;
        }

        [CLSCompliant(false)]
        public UInt64 ReadUInt64()
        {
            UInt64 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (UInt64)(ReadUInt8() << 56);
                value |= ((UInt64)ReadUInt8() << 48);
                value |= ((UInt64)ReadUInt8() << 40);
                value |= ((UInt64)ReadUInt8() << 32);
                value |= ((UInt64)ReadUInt8() << 24);
                value |= ((UInt64)ReadUInt8() << 16);
                value |= ((UInt64)ReadUInt8() << 8);
                value |= (UInt64)(UInt32)(ReadUInt8());
            }
            else
            {
                value = (UInt64)(ReadUInt8());
                value |= ((UInt64)ReadUInt8() << 8);
                value |= ((UInt64)ReadUInt8() << 16);
                value |= ((UInt64)ReadUInt8() << 24);
                value |= ((UInt64)ReadUInt8() << 32);
                value |= ((UInt64)ReadUInt8() << 40);
                value |= ((UInt64)ReadUInt8() << 48);
                value |= ((UInt64)ReadUInt8() << 56);
            }

            return value;
        }

        public Int16 ReadInt16()
        {
            Int16 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (Int16)(ReadUInt8() << 8);
                value |= (Int16)(ReadUInt8());
            }
            else
            {
                value = (Int16)(ReadUInt8());
                value |= (Int16)(ReadUInt8() << 8);
            }

            return value;
        }


        public Int32 ReadInt24()
        {
            Int32 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (Int32)(ReadUInt8() << 8);
                value |= (Int32)(ReadUInt8() << 16);
                value |= (Int32)(ReadUInt8());
            }
            else
            {
                value = (Int32)(ReadUInt8());
                value |= (Int32)(ReadUInt8() << 8);
                value |= (Int32)(ReadUInt8() << 16);
            }

            return value;
        }

        public Int32 ReadInt32()
        {
            Int32 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (Int32)(ReadUInt8() << 24);
                value |= (Int32)(ReadUInt8() << 16);
                value |= (Int32)(ReadUInt8() << 8);
                value |= (Int32)(ReadUInt8());
            }
            else
            {
                value = (Int32)(ReadUInt8());
                value |= (Int32)(ReadUInt8() << 8);
                value |= (Int32)(ReadUInt8() << 16);
                value |= (Int32)(ReadUInt8() << 24);
            }

            return value;
        }

        public Int64 ReadInt64()
        {
            Int64 value = 0;

            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                value = (Int64)(ReadUInt8() << 56);
                value |= ((Int64)ReadUInt8() << 48);
                value |= ((Int64)ReadUInt8() << 40);
                value |= ((Int64)ReadUInt8() << 32);
                value |= ((Int64)ReadUInt8() << 24);
                value |= ((Int64)ReadUInt8() << 16);
                value |= ((Int64)ReadUInt8() << 8);
                value |= (Int64)(UInt32)(ReadUInt8());
            }
            else
            {
                value = (Int64)(ReadUInt8());
                value |= ((Int64)ReadUInt8() << 8);
                value |= ((Int64)ReadUInt8() << 16);
                value |= ((Int64)ReadUInt8() << 24);
                value |= ((Int64)ReadUInt8() << 32);
                value |= ((Int64)ReadUInt8() << 40);
                value |= ((Int64)ReadUInt8() << 48);
                value |= ((Int64)ReadUInt8() << 56);
            }

            return value;
        }

        public String ReadString(int length)
        {
            Byte[] buffer = new Byte[length];
            String value;

            buffer = ReadBytes(length);
            value = ASCIIEncoding.ASCII.GetString(buffer, 0, buffer.Length);

            return value;
        }

        public Byte[] ReadBytes(int length)
        {
            Byte[] value = new Byte[length];

            myStream.Read(value, 0, length);

            return value;
        }

        public Byte ReadBcd8()
        {
            Byte buffer = (Byte)myStream.ReadByte();
            Byte value;

            value = (Byte)((buffer & 0x0F));
            value += (Byte)(10 * ((buffer >> 4) & 0x0F));

            return value;
        }

        [CLSCompliant(false)]
        public UInt16 ReadBcd16()
        {
            UInt16 buffer = ReadUInt16();
            UInt16 value;
            if (myByteEndianess == ByteEndianess.BigEndian)
            {
                value = (UInt16)((buffer & 0x0F));
                value += (UInt16)(10 * ((buffer >> 4) & 0x0F));
                value += (UInt16)(100 * ((buffer >> 8) & 0x0F));
                value += (UInt16)(1000 * ((buffer >> 12) & 0x0F));
            }
            else
            {
                value = (UInt16)(1000 * (buffer & 0x0F));
                value += (UInt16)(100 * ((buffer >> 4) & 0x0F));
                value += (UInt16)(10 * ((buffer >> 8) & 0x0F));
                value += (UInt16)((buffer >> 12) & 0x0F);
            }

            return value;
        }

        #endregion

        #region Write Methods

        public void WriteUInt8(Byte value)
        {
            // Change bit-order if appropriate.
            if (BitEndianess.Lsb == myBitEndianess) value = (byte)IPAddress.HostToNetworkOrder(value);

            myStream.WriteByte(value);
        }

        [CLSCompliant(false)]
        public void WriteUInt16(UInt16 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
            }
        }

        [CLSCompliant(false)]
        public void WriteUInt24(UInt32 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
            }
        }

        [CLSCompliant(false)]
        public void WriteUInt24(Int32 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
            }
        }

        [CLSCompliant(false)]
        public void WriteUInt32(UInt32 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 24));
            }
        }

        [CLSCompliant(false)]
        public void WriteUInt64(UInt64 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 56));
                WriteUInt8((Byte)(value >> 48));
                WriteUInt8((Byte)(value >> 40));
                WriteUInt8((Byte)(value >> 32));
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 32));
                WriteUInt8((Byte)(value >> 40));
                WriteUInt8((Byte)(value >> 48));
                WriteUInt8((Byte)(value >> 56));
            }
        }

        public void WriteInt16(Int16 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
            }
        }

        public void WriteInt32(Int32 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 24));
            }
        }

        public void WriteInt64(Int64 value)
        {
            if (ByteEndianess.BigEndian == myByteEndianess)
            {
                WriteUInt8((Byte)(value >> 56));
                WriteUInt8((Byte)(value >> 48));
                WriteUInt8((Byte)(value >> 40));
                WriteUInt8((Byte)(value >> 32));
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)value);
            }
            else
            {
                WriteUInt8((Byte)value);
                WriteUInt8((Byte)(value >> 8));
                WriteUInt8((Byte)(value >> 16));
                WriteUInt8((Byte)(value >> 24));
                WriteUInt8((Byte)(value >> 32));
                WriteUInt8((Byte)(value >> 40));
                WriteUInt8((Byte)(value >> 48));
                WriteUInt8((Byte)(value >> 56));
            }
        }

        public void WriteString(String value)
        {
            Byte[] buffer = ASCIIEncoding.ASCII.GetBytes(value);
            myStream.Write(buffer, 0, buffer.Length);
        }

        public void WriteBytes(Byte[] value)
        {
            myStream.Write(value, 0, value.Length);
        }

        public void WriteBytes(Byte[] value, int offset, int length)
        {
            myStream.Write(value, offset, length);
        }

        #endregion

        #region Peek Methods

        public Byte PeekUInt8()
        {
            Byte value = ReadUInt8();
            myStream.Position--;
            return value;
        }

        [CLSCompliant(false)]
        public UInt16 PeekUInt16()
        {
            UInt16 value = ReadUInt16();
            myStream.Position -= sizeof(UInt16);
            return value;
        }

        [CLSCompliant(false)]
        public UInt32 PeekUInt24()
        {
            UInt32 value = ReadUInt24();
            myStream.Position -= sizeof(UInt16) + sizeof(Byte);
            return value;
        }

        [CLSCompliant(false)]
        public UInt32 PeekUInt32()
        {
            UInt32 value = ReadUInt32();
            myStream.Position -= sizeof(UInt32);
            return value;
        }

        [CLSCompliant(false)]
        public UInt64 PeekUInt64()
        {
            UInt64 value = ReadUInt64();
            myStream.Position -= sizeof(UInt64);
            return value;
        }

        public Int16 PeekInt16()
        {
            Int16 value = ReadInt16();
            myStream.Position -= sizeof(Int16);
            return value;
        }

        public Int32 PeekInt24()
        {
            Int32 value = ReadInt24();
            myStream.Position -= sizeof(Int16) + sizeof(Byte);
            return value;
        }

        public Int32 PeekInt32()
        {
            Int32 value = ReadInt32();
            myStream.Position -= sizeof(Int32);
            return value;
        }

        public Int64 PeekInt64()
        {
            Int64 value = ReadInt64();
            myStream.Position -= sizeof(Int64);
            return value;
        }

        public String PeekString(int length)
        {
            String output = ReadString(length);
            Position -= length;
            return output;
        }

        public Byte[] PeekBytes(int length)
        {
            Byte[] output = ReadBytes(length);
            Position -= length;
            return output;
        }

        public Byte PeekBcd8()
        {
            Byte output = ReadBcd8();
            Position -= sizeof(Byte);
            return output;
        }

        [CLSCompliant(false)]
        public UInt16 PeekBcd16()
        {
            UInt16 output = ReadBcd16();
            Position -= sizeof(Byte);
            return output;
        }

        #endregion

        #region Static Conversion Methods


        public static byte[] ConvertUInt8(Byte value, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            // Change bit-order if appropriate.
            byte[] buffer = new byte[1];
            if (BitEndianess.Lsb == bitEndianess) value = (byte)IPAddress.HostToNetworkOrder(value);

            buffer[0] = value;

            return buffer;
        }

        [CLSCompliant(false)]
        public static byte[] ConvertUInt16(UInt16 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[2];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 8));
                buffer[1] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
            }
            return buffer;
        }

        [CLSCompliant(false)]
        public static byte[] ConvertUInt24(UInt32 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[3];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 16));
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)(value >> 16));
            }
            return buffer;
        }


        [CLSCompliant(false)]
        public static byte[] ConvertUInt32(UInt32 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[4];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 24));
                buffer[1] = ((Byte)(value >> 16));
                buffer[2] = ((Byte)(value >> 8));
                buffer[3] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)(value >> 16));
                buffer[3] = ((Byte)(value >> 24));
            }
            return buffer;
        }

        [CLSCompliant(false)]
        public static byte[] ConvertUInt64(UInt64 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[8];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 56));
                buffer[1] = ((Byte)(value >> 48));
                buffer[2] = ((Byte)(value >> 40));
                buffer[3] = ((Byte)(value >> 32));
                buffer[4] = ((Byte)(value >> 24));
                buffer[5] = ((Byte)(value >> 16));
                buffer[6] = ((Byte)(value >> 8));
                buffer[7] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)(value >> 16));
                buffer[3] = ((Byte)(value >> 24));
                buffer[4] = ((Byte)(value >> 32));
                buffer[5] = ((Byte)(value >> 40));
                buffer[6] = ((Byte)(value >> 48));
                buffer[7] = ((Byte)(value >> 56));
            }
            return buffer;
        }

        public static byte[] ConvertInt16(Int16 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[2];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 8));
                buffer[1] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
            }
            return buffer;
        }

        public static byte[] ConvertInt32(Int32 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[4];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 24));
                buffer[1] = ((Byte)(value >> 16));
                buffer[2] = ((Byte)(value >> 8));
                buffer[3] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)(value >> 16));
                buffer[3] = ((Byte)(value >> 24));
            }
            return buffer;
        }

        public static byte[] ConvertInt64(Int64 value, ByteEndianess byteEndianess = ByteEndianess.LittleEndian, BitEndianess bitEndianess = BitEndianess.Msb)
        {
            byte[] buffer = new byte[8];
            if (ByteEndianess.BigEndian == byteEndianess)
            {
                buffer[0] = ((Byte)(value >> 56));
                buffer[1] = ((Byte)(value >> 48));
                buffer[2] = ((Byte)(value >> 40));
                buffer[3] = ((Byte)(value >> 32));
                buffer[4] = ((Byte)(value >> 24));
                buffer[5] = ((Byte)(value >> 16));
                buffer[6] = ((Byte)(value >> 8));
                buffer[7] = ((Byte)value);
            }
            else
            {
                buffer[0] = ((Byte)value);
                buffer[1] = ((Byte)(value >> 8));
                buffer[2] = ((Byte)(value >> 16));
                buffer[3] = ((Byte)(value >> 24));
                buffer[4] = ((Byte)(value >> 32));
                buffer[5] = ((Byte)(value >> 40));
                buffer[6] = ((Byte)(value >> 48));
                buffer[7] = ((Byte)(value >> 56));
            }
            return buffer;
        }

        public static byte[] ConvertString(String value)
        {
            Byte[] buffer = ASCIIEncoding.ASCII.GetBytes(value);
            return buffer;
        }

        #endregion

        public byte[] ToArray()
        {
            byte[] output = new byte[myStream.Length];

            long position = myStream.Position;                          // store the position
            myStream.Position = 0;                                      // reset the position
            myStream.Read(output, 0, (int)myStream.Length);             // read
            myStream.Position = position;                               // restore position

            return output;
        }

        public void Clear()
        {
            myStream.SetLength(0);
        }


        private ByteEndianess myByteEndianess = ByteEndianess.LittleEndian;
        private BitEndianess myBitEndianess = BitEndianess.Msb;

        private byte myBitPosition;

        #region IDisposable Members

        public void Dispose()
        {
            if (myStream != null) myStream.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion
    }

    /// <summary>
    /// The Byte-wise endianess of the supplied data.
    /// </summary>
    public enum ByteEndianess
    {
        /// <summary>
        /// Big-Endian, The most-significant Byte appears first (Default).
        /// </summary>
        BigEndian,

        /// <summary>
        /// Little-Endian, The least-significant Byte appears first.
        /// </summary>
        LittleEndian,
    }

    /// <summary>
    /// The bit-wise endianess of the supplied data.
    /// </summary>
    public enum BitEndianess
    {
        /// <summary>
        /// Most-Significant Bit first (Default)
        /// </summary>
        Msb,

        /// <summary>
        /// Least-Significant Bit first
        /// </summary>
        Lsb
    }
}
