using CardFramework.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace CardFramework.Applications.PACSAM
{
    [XmlType("AES128")]
    public class PACSAMAES128KeyRecord : PACSAMKeyRecord
    {
        public const int Length = 16;

        [XmlElement(DataType = "hexBinary")]
        public byte[] Value;

        public PACSAMAES128KeyRecord()
        {
            Value = new byte[Length];
        }

        public PACSAMAES128KeyRecord(PACSAMAES128KeyRecord copyObject)
        {
            copyObject.CopyTo(this, true);
        }

        public override byte[] GetHashInputData()
        {
            var data = new BinaryParser();

            // Get the basic key record data
            data?.WriteBytes(base.GetHashInputData());

            // Key Value
            data?.WriteBytes(Value);

            // Done
            return data.ToArray();
        }

        public override void Generate()
        {
            var aes = new AesCryptoServiceProvider();
            aes.KeySize = (Length * 8); // Convert to bits
            aes.GenerateKey();
            Value = new byte[aes.Key.Length];
            aes.Key.CopyTo(Value, 0);

            // Update the hash for this record
            UpdateHash();
        }

        public override byte[] PackRecord(string element = "")
        {
            BinaryParser record = new BinaryParser(ByteEndianess.BigEndian);

            // Id
            record.WriteInt16(Id);

            // Version
            record.WriteUInt8(Version);

            // Attribute
            record.WriteUInt16((ushort)Attributes);

            // Name
            record.WriteString(Name.PadRight(PACSAMKey.MaxNameLength));

            // Key Value
            record.WriteBytes(Value);

            // Done
            return record.ToArray();
        }



        public override void CopyTo(PACSAMKeyRecord to, bool includeKey = false)
        {
            base.CopyTo(to);

            if (includeKey)
            {
                (to as PACSAMAES128KeyRecord).Value = Value.ToArray();
            }
        }

        public override PACSAMKeyRecord Clone(bool includeKey = false)
        {
            PACSAMAES128KeyRecord instance = new PACSAMAES128KeyRecord();
            CopyTo(instance, includeKey);
            return instance;
        }

        public override void ExportParts(params PACSAMKeyRecord[] parts)
        {
            // There must be at least 3 or more parts
            if (parts.Length < 3) throw new ArgumentException(@"ExportParts: There must be at 3 or more parts to export to!");

            // Create part 0
            parts[0] = new PACSAMAES128KeyRecord(this);

            // Iterate through the parts from 1 to n (skipping the first, which will hold the XOR result)
            for (int i = 1; i < parts.Length; i++)
            {
                // Generate the part
                parts[i] = new PACSAMAES128KeyRecord(this);

                var pI = (parts[i] as PACSAMAES128KeyRecord);
                var p0 = (parts[0] as PACSAMAES128KeyRecord);

                pI.Value = Crypto.CreateRandomEntropy(Value.Length);
                p0.Value = Crypto.XorArray(p0.Value, pI.Value);
            }
        }

        public override void ImportParts(params PACSAMKeyRecord[] parts)
        {
            // There must be at least 3 or more parts
            if (parts.Length < 3) throw new ArgumentException(@"ExportParts: There must be at 3 or more parts to export to!");

            for (int i = 1; i < parts.Length; i++)
            {
                // Validate each part has the same hash
                if (!parts[i].Hash.SequenceEqual(parts[0].Hash))
                    throw new InvalidDataException(@"ImportParts: Hash values do not match for supplied key parts");
            }

            // Copy part 0
            parts[0].CopyTo(this, true);

            // Iterate through the parts from 1 to n (skipping the first, which will hold the XOR result)
            for (int i = 1; i < parts.Length; i++)
            {
                var pI = (parts[i] as PACSAMAES128KeyRecord);

                Value = Crypto.XorArray(Value, pI.Value);
            }
        }

        public override bool IsInitialised()
        {
            return (Value != null && Value.Length == Length);
        }
    }
}
