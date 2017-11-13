using CardFramework.Applications.Plaid;
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
    [XmlType("PLAID")]
    public class PACSAMPlaidKeyRecord : PACSAMKeyRecord
    {
        public const int LengthFAKey = 16; // In bits
        public const int LengthIAKey = 256; // In bits
        public const int LengthFAKeyBits = 128; // In bits
        public const int LengthIAKeyBits = 2048; // In bits

        public const byte IAKeyPElement = 0;
        public const byte IAKeyQElement = 1;
        public const byte IAKeyPQElement = 2;
        public const byte IAKeyDPElement = 3;
        public const byte IAKeyDQElement = 4;
        public const byte IAKeyModulusElement = 5;
        public const byte IAKeyExponentElement = 6;
        public const byte FAKeyElement = 7;

        public RSAKey IAKey;

        [XmlElement(DataType = "hexBinary", IsNullable = false)]
        public byte[] FAKey;

        public PACSAMPlaidKeyRecord()
        {
            IAKey = new RSAKey();
            FAKey = new byte[LengthFAKeyBits];
        }

        public PACSAMPlaidKeyRecord(PACSAMPlaidKeyRecord copyObject)
        {
            copyObject.CopyTo(this, true);
        }

        public override void Generate()
        {
            // IA Key
            var rsa = new RSACryptoServiceProvider(LengthIAKeyBits).ExportParameters(true);
            IAKey = new RSAKey(rsa);

            // FA Key
            var aes = new AesCryptoServiceProvider();
            aes.KeySize = LengthFAKeyBits;
            aes.GenerateKey();
            FAKey = new byte[aes.Key.Length];
            aes.Key.CopyTo(FAKey, 0);

            // Update the Hash
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
            switch (element)
            {
                case "IAKEY_P":
                    record.WriteBytes(IAKey.P);
                    break;

                case "IAKEY_Q":
                    record.WriteBytes(IAKey.Q);
                    break;

                case "IAKEY_PQ":
                    record.WriteBytes(IAKey.PQ);
                    break;

                case "IAKEY_DP":
                    record.WriteBytes(IAKey.DP);
                    break;

                case "IAKEY_DQ":
                    record.WriteBytes(IAKey.DQ);
                    break;

                case "IAKEY_D":
                    record.WriteBytes(IAKey.D);
                    break;

                case "IAKEY_MODULUS":
                    record.WriteBytes(IAKey.Modulus);
                    break;

                case "IAKEY_EXPONENT":
                    record.WriteBytes(IAKey.Exponent);
                    break;


                case "FAKEY":
                    record.WriteBytes(FAKey);
                    break;

                default:
                    throw new ArgumentException("Invalid key element");

            }

            // Done
            return record.ToArray();
        }

        public override byte[] GetHashInputData()
        {
            var data = new BinaryParser();

            // Get the basic key record data
            data?.WriteBytes(base.GetHashInputData());

            // IAKey
            data?.WriteBytes(IAKey.GetHashInputData());

            // FAKey
            data?.WriteBytes(FAKey);

            // Done
            return data.ToArray();
        }

        public override void CopyTo(PACSAMKeyRecord to, bool includeKey = false)
        {
            base.CopyTo(to);

            if (includeKey)
            {
                if (IAKey == null)
                {
                    throw new ApplicationException(@"The 'IAKey' element of an initialised key is missing.");
                }

                if (IAKey.P == null ||
                    IAKey.Q == null ||
                    IAKey.PQ == null ||
                    IAKey.DP == null ||
                    IAKey.DQ == null ||
                    IAKey.Modulus == null ||
                    IAKey.Exponent == null)
                {
                    throw new ApplicationException(@"One or more 'IAKey' sub-elements of an initialised key are missing.");
                }

                if (FAKey == null)
                {
                    throw new ApplicationException(@"The 'FAKey' element of an initialised key is missing.");
                }

                (to as PACSAMPlaidKeyRecord).IAKey = new RSAKey(IAKey);
                (to as PACSAMPlaidKeyRecord).FAKey = FAKey.ToArray();
            }
        }

        public override PACSAMKeyRecord Clone(bool includeKey = false)
        {
            PACSAMPlaidKeyRecord instance = new PACSAMPlaidKeyRecord();
            CopyTo(instance, includeKey);
            return instance;
        }

        public override void ExportParts(params PACSAMKeyRecord[] parts)
        {
            // There must be at least 3 or more parts
            if (parts.Length < 3) throw new ArgumentException(@"ExportParts: There must be at 3 or more parts to export to!");

            // Create part 0
            parts[0] = new PACSAMPlaidKeyRecord(this);

            // Iterate through the parts from 1 to n (skipping the first, which will hold the XOR result)
            for (int i = 1; i < parts.Length; i++)
            {
                // Generate the part
                parts[i] = new PACSAMPlaidKeyRecord(this);

                var pI = (parts[i] as PACSAMPlaidKeyRecord);
                var p0 = (parts[0] as PACSAMPlaidKeyRecord);

                pI.IAKey.P = Crypto.CreateRandomEntropy(IAKey.P.Length);
                p0.IAKey.P = Crypto.XorArray(p0.IAKey.P, pI.IAKey.P);

                pI.IAKey.Q = Crypto.CreateRandomEntropy(IAKey.Q.Length);
                p0.IAKey.Q = Crypto.XorArray(p0.IAKey.Q, pI.IAKey.Q);

                pI.IAKey.PQ = Crypto.CreateRandomEntropy(IAKey.PQ.Length);
                p0.IAKey.PQ = Crypto.XorArray(p0.IAKey.PQ, pI.IAKey.PQ);

                pI.IAKey.DP = Crypto.CreateRandomEntropy(IAKey.DP.Length);
                p0.IAKey.DP = Crypto.XorArray(p0.IAKey.DP, pI.IAKey.DP);

                pI.IAKey.DQ = Crypto.CreateRandomEntropy(IAKey.DQ.Length);
                p0.IAKey.DQ = Crypto.XorArray(p0.IAKey.DQ, pI.IAKey.DQ);

                pI.IAKey.D = Crypto.CreateRandomEntropy(IAKey.D.Length);
                p0.IAKey.D = Crypto.XorArray(p0.IAKey.D, pI.IAKey.D);

                pI.IAKey.Modulus = Crypto.CreateRandomEntropy(IAKey.Modulus.Length);
                p0.IAKey.Modulus = Crypto.XorArray(p0.IAKey.Modulus, pI.IAKey.Modulus);

                pI.IAKey.Exponent = Crypto.CreateRandomEntropy(IAKey.Exponent.Length);
                p0.IAKey.Exponent = Crypto.XorArray(p0.IAKey.Exponent, pI.IAKey.Exponent);

                pI.FAKey = Crypto.CreateRandomEntropy(FAKey.Length);
                p0.FAKey = Crypto.XorArray(p0.FAKey, pI.FAKey);
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
                var pI = (parts[i] as PACSAMPlaidKeyRecord);

                // IAKey Modulus
                IAKey.P = Crypto.XorArray(IAKey.P, pI.IAKey.P);
                IAKey.Q = Crypto.XorArray(IAKey.Q, pI.IAKey.Q);
                IAKey.PQ = Crypto.XorArray(IAKey.PQ, pI.IAKey.PQ);
                IAKey.DP = Crypto.XorArray(IAKey.DP, pI.IAKey.DP);
                IAKey.DQ = Crypto.XorArray(IAKey.DQ, pI.IAKey.DQ);
                IAKey.D = Crypto.XorArray(IAKey.D, pI.IAKey.D);
                IAKey.Modulus = Crypto.XorArray(IAKey.Modulus, pI.IAKey.Modulus);
                IAKey.Exponent = Crypto.XorArray(IAKey.Exponent, pI.IAKey.Exponent);

                // FAKey
                FAKey = Crypto.XorArray(FAKey, pI.FAKey);
            }
        }

        public override bool IsInitialised()
        {
            if (IAKey == null) return false;
            if (IAKey.P == null) return false;
            if (IAKey.Q == null) return false;
            if (IAKey.PQ == null) return false;
            if (IAKey.DP == null) return false;
            if (IAKey.DQ == null) return false;
            if (IAKey.Modulus == null) return false;
            if (IAKey.Exponent == null) return false;

            if (FAKey == null || FAKey.Length != LengthFAKey) return false;

            return true;
        }

    }
}