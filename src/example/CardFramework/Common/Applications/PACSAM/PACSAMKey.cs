using CardFramework.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace CardFramework.Applications.PACSAM
{
    public class PACSAMKey
    {
        public const int MaxNameLength = 25;

        public PACSAMKey()
        {
        }

        public PACSAMKey(byte[] header) : this()
        {
            BinaryParser parser = new BinaryParser(header, ByteEndianess.BigEndian);

            // Key Index
            Index = parser.ReadInt16();

            // Type
            KeyType = (PACSAMKeyType)parser.ReadUInt8();

            // Id
            Id = parser.ReadInt16();

            // Version
            Version = parser.ReadUInt8();

            // Attributes
            Attributes = (PACSAMKeyAttribute)parser.ReadUInt16();

            // Name
            Name = parser.ReadString(MaxNameLength).Trim();
        }

        public override string ToString()
        {
            return string.Format("INDEX: {0:X4}, TYPE: {1}, ID: {2:X4}, VERSION: {3:X2}, NAME='{4}'", Index, KeyType, Id, Version, Name);
        }

        public short Index;
        public PACSAMKeyType KeyType;
        public short Id;
        public byte Version;
        public string Name = @"";
        public PACSAMKeyAttribute Attributes;
    }
}
