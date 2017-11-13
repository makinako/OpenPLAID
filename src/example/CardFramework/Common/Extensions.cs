using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace CardFramework
{
    public static class Extensions
    {
        /*
         * STRING EXTENSIONS
         */
        static Regex hexRegex;

        static Extensions()
        {
            // For C-style hex notation (0xFF) you can use @"\A\b(0[xX])?[0-9a-fA-F]+\b\Z"
            hexRegex = new Regex(@"\A\b[0-9a-fA-F]+\b\Z", RegexOptions.Compiled);
        }

        public static bool IsHex(this string value)
        {
            return hexRegex.IsMatch(value);
        }

        public static string ToHexString(this byte[] value, string separator = @"")
        {
            return BitConverter.ToString(value).Replace("-", separator);
        }

        public static byte[] HexToArray(this string value)
        {
            // Trim all whitespace
            value = value.Replace("-", "");
            value = value.Replace(" ", "");
            value = value.Replace(":", "");
            value = value.Replace(";", "");
            value = value.Replace("[", "");
            value = value.Replace("]", "");

            var result = new byte[(value.Length + 1) / 2];
            var offset = 0;
            if (value.Length % 2 == 1)
            {
                // If length of input is odd, the first character has an implicit 0 prepended.
                result[0] = (byte)Convert.ToUInt32(value[0] + "", 16);
                offset = 1;
            }
            for (int i = 0; i < value.Length / 2; i++)
            {
                result[i + offset] = (byte)Convert.ToUInt32(value.Substring(i * 2 + offset, 2), 16);
            }
            return result;
        }

        /*
         * Byte Array Extensions
         */

        public static byte[] Append(this byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Array.Copy(a, 0, c, 0, a.Length);
            Array.Copy(b, 0, c, a.Length, b.Length);
            return c;
        }

        public static byte[] Prepend(this byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Array.Copy(b, 0, c, 0, b.Length);
            Array.Copy(a, 0, c, b.Length, a.Length);
            return c;
        }

        public static byte[] Append(this byte[] a, byte b)
        {
            byte[] c = new byte[a.Length + 1];
            Array.Copy(a, 0, c, 0, a.Length);
            c[a.Length] = b; // Last byte
            return c;
        }

        public static byte[] Prepend(this byte[] a, byte b)
        {
            byte[] c = new byte[a.Length + 1];
            Array.Copy(a, 0, c, 1, a.Length);
            c[0] = b; // First byte
            return c;
        }

        public static byte[] Append(this byte a, byte[] b)
        {
            byte[] c = new byte[b.Length + 1];
            c[0] = a; // First byte
            Array.Copy(b, 0, c, 1, b.Length);
            return c;
        }

        public static byte[] Prepend(this byte a, byte[] b)
        {
            byte[] c = new byte[b.Length + 1];
            Array.Copy(b, 0, c, 0, b.Length);
            c[b.Length] = a; // Last byte
            return c;
        }

        public static byte[] PadRight(this byte[] a, int padToLength, byte padValue = 0)
        {
            if (padToLength <= a?.Length) throw new ArgumentException(@"padToLength is shorter than input data");
            byte[] b = new byte[padToLength - a.Length];
            for (int i = 0; i < b.Length; i++) b[i] = padValue;
            return a.Append(b);
        }

        public static byte[] PadLeft(this byte[] a, int padToLength, byte padValue = 0)
        {
            if (padToLength <= a?.Length) throw new ArgumentException(@"padToLength is shorter than input data");
            byte[] b = new byte[padToLength - a.Length];
            for (int i = 0; i < b.Length; i++) b[i] = padValue;
            return b.Append(a);
        }

        public class ExceptionSourceInfo
        {
            public string MethodName;
            public string MethodSignature;
            public int Line;
            public int Column;
            public string FileName;
            public string FilePath;

            public string ToString(bool verbose = false)
            {
                if (verbose)
                {
                    return $"{FilePath}({Line},{Column}):{MethodSignature}";
                }
                else
                {
                    return $"{FileName}({Line},{Column}):{MethodName}";
                }
            }

            public override string ToString()
            {
                return ToString(false);
            }
        }

        public static ExceptionSourceInfo GetSourceInfo(this Exception ex, bool fileInfo = true)
        {
            var st = new StackTrace(ex, fileInfo);
            var frame = st.GetFrame(st.FrameCount - 1);
            var source = new ExceptionSourceInfo();

            if (fileInfo)
            {
                source.FilePath = frame.GetFileName();
                source.FileName = new FileInfo(source.FilePath).Name;
                source.Line = frame.GetFileLineNumber();
                source.Column = frame.GetFileColumnNumber();
            }

            var method = frame.GetMethod();
            source.MethodName = method.Name;
            source.MethodSignature = method.ToString();

            return source;
        }
    }
}
