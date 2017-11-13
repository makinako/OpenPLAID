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
using System.Globalization;

namespace CardFramework.Helpers
{
    public static class Converters
    {
        public static bool CompareArray<T>(T[] first, T[] second) where T : IEquatable<T>
        {
            // Check validity
            if (first == null && second == null) return true;
            if (first == null || second == null) return false;

            // Check length
            if (first.Length != second.Length) return false;

            // Check values
            for (int i = 0; i < first.Length; i++)
            {
                if (!first[i].Equals(second[i])) return false;
            }

            // It passed!
            return true;
        }

        public static int Bitcount(int n)
        {
            int count = 0;
            while (n != 0)
            {
                count++;
                n &= (n - 1);
            }
            return count;
        }
        public static int Bitcount(uint n)
        {
            int count = 0;
            while (n != 0)
            {
                count++;
                n &= (n - 1);
            }
            return count;
        }

        public static int Bitcount(long n)
        {
            int count = 0;
            while (n != 0)
            {
                count++;
                n &= (n - 1);
            }
            return count;
        }

        public static int Bitcount(ulong n)
        {
            int count = 0;
            while (n != 0)
            {
                count++;
                n &= (n - 1);
            }
            return count;
        }

        public static bool IsHexString(String data)
        {
            foreach (char c in data)
            {
                if (!IsHexChar(c)) return false;
            }
            return true;
        }

        public static bool IsHexChar(char data)
        {
            return ((data >= '0' && data <= '9') ||
                    (data >= 'a' && data <= 'f') ||
                    (data >= 'A' && data <= 'F'));
        }

        public static byte[] StringToByteArray(String data)
        {
            // Filter out some common value separators first
            data = data.Replace(" ", "");
            data = data.Replace("-", "");
            data = data.Replace(",", "");

            if (!IsHexString(data)) throw new ArgumentException(@"Invalid hexidecimal input.", "data");

            int NumberChars = data.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static string ByteArrayToAscii(byte[] data)
        {
            return System.Text.Encoding.ASCII.GetString(data);
        }

        public static string ByteArrayToString(byte[] data)
        {
            StringBuilder result = new StringBuilder();
            foreach (byte b in data)
            {
                result.Append(String.Format(CultureInfo.InvariantCulture, "{0:X2}", b));
            }
            return result.ToString();
        }

        public static string ByteArrayToString(byte[] data, int offset, int len)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < len; i++)
            {
                result.Append(String.Format(CultureInfo.InvariantCulture, "{0:X2}", data[offset + i]));
            }
            return result.ToString();
        }

        public static byte SwapBitOrder(byte value)
        {
            byte result = 0;

            for (byte i = 0; i < 8; i++)
            {
                result <<= 1;
                result |= (byte)(value & 1);
                value >>= 1;
            }

            return result;
        }

        public static byte[] SwapByteOrder(byte[] value)
        {
            // FIXME: Don't create the second buffer
            byte[] buffer = new byte[value.Length];

            for (int i = 0; i < value.Length; i++)
            {
                buffer[value.Length - i - 1] = value[i];
            }

            return buffer;
        }

        public static Int32 HexToInt32(string value)
        {
            return Int32.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        public static Int64 HexToInt64(string value)
        {
            return Int64.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }



        public static void IntToArray(Int64 value, byte[] dest, int offset)
        {
            int shift = sizeof(Int64);

            for (int i = 0; i < sizeof(Int64); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }

        public static void IntToArray(UInt64 value, byte[] dest, int offset)
        {
            int shift = sizeof(UInt64);

            for (int i = 0; i < sizeof(UInt64); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }


        public static void IntToArray(Int32 value, byte[] dest, int offset)
        {
            int shift = sizeof(Int32);

            for (int i = 0; i < sizeof(Int32); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }


        public static void IntToArray(UInt32 value, byte[] dest, int offset)
        {
            int shift = sizeof(Int32);

            for (int i = 0; i < sizeof(UInt32); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }

        public static void IntToArray(Int16 value, byte[] dest, int offset)
        {
            int shift = sizeof(Int16);

            for (int i = 0; i < sizeof(Int16); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }


        public static void IntToArray(UInt16 value, byte[] dest, int offset)
        {
            int shift = sizeof(UInt16);

            for (int i = 0; i < sizeof(UInt16); i++)
            {
                shift--;
                dest[offset + shift] = (byte)((value >> (8 * i) & 0xFF));
            }
        }


        public static byte[] IntToArray(Int16 value)
        {
            byte[] result = new byte[sizeof(Int16)];
            int shift = sizeof(Int16);

            for (int i = 0; i < sizeof(Int16); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }

        public static byte[] IntToArray(UInt16 value)
        {
            byte[] result = new byte[sizeof(UInt16)];
            int shift = sizeof(UInt16);

            for (int i = 0; i < sizeof(UInt16); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }


        public static byte[] IntToArray(Int32 value)
        {
            byte[] result = new byte[sizeof(Int32)];
            int shift = sizeof(Int32);

            for (int i = 0; i < sizeof(Int32); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }

        public static byte[] IntToArray(UInt32 value)
        {
            byte[] result = new byte[sizeof(UInt32)];
            int shift = sizeof(UInt32);

            for (int i = 0; i < sizeof(UInt32); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }


        public static byte[] IntToArray(Int64 value)
        {
            byte[] result = new byte[sizeof(Int64)];
            int shift = sizeof(Int64);

            for (int i = 0; i < sizeof(Int64); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }

        public static byte[] IntToArray(UInt64 value)
        {
            byte[] result = new byte[sizeof(UInt64)];
            int shift = sizeof(UInt64);

            for (int i = 0; i < sizeof(UInt64); i++)
            {
                shift--;
                result[shift] = (byte)((value >> (8 * i) & 0xFF));
            }

            return result;
        }

    }
}
