using CardFramework.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace CardFramework.Applications.PACSAM
{
    [XmlRoot("KeyRecord")]
    [XmlType("KeyRecord")]
    [XmlInclude(typeof(PACSAMKeyFile))]
    [XmlInclude(typeof(PACSAMPlaidKeyRecord))]
    [XmlInclude(typeof(PACSAMAES128KeyRecord))]
    [XmlInclude(typeof(PACSAMTDEA2KeyRecord))]
    public abstract class PACSAMKeyRecord
    {
        private static SHA256 cspChecksum = SHA256.Create();
        private static object checksumLock = new object();

        public PACSAMKeyRecord()
        {
        }

        [XmlIgnore]
        public short Id
        {
            get
            {
                var value = (short)(IdBytes[0] << 8);
                value |= (short)(IdBytes[1]);
                return value;
            }
            set
            {
                IdBytes[0] = (byte)((value >> 8) & 0xFF);
                IdBytes[1] = (byte)(value & 0xFF);
            }
        }

        [XmlAttribute("id", DataType = "hexBinary")]
        public byte[] IdBytes = new byte[2];

        [XmlAttribute("version")]
        public byte Version;

        [XmlAttribute("name")]
        public string Name
        {
            get
            {
                return _name;
            }
            set
            {
                if (String.IsNullOrEmpty(value)) throw new ArgumentException("Name must not be null");
                if (value.Length > PACSAMKey.MaxNameLength) throw new ArgumentException("Name field is too long");
                _name = value;
            }
        }

        private string _name = @"";

        [XmlElement(DataType = "hexBinary")]
        public byte[] Hash = new byte[0];

        [XmlElement("Attributes")]
        public PACSAMKeyAttribute? Attributes;

        /// <summary>
        /// Generates key values for this key record
        /// </summary>
        public abstract void Generate();

        public virtual byte[] GetHashInputData()
        {
            BinaryParser data = new BinaryParser();

            // Id
            data.WriteBytes(IdBytes);

            // Version
            data.WriteUInt8(Version);

            // Name
            data.WriteString(Name);

            return data.ToArray();
        }

        public void UpdateHash()
        {
            lock (checksumLock)
            {
                Hash = cspChecksum.ComputeHash(GetHashInputData());
            }
        }

        public bool VerifyHash()
        {
            lock (checksumLock)
            {
                byte[] comparison = cspChecksum.ComputeHash(GetHashInputData());
                return Hash.SequenceEqual(comparison);
            }            
        }

        public virtual void CopyTo(PACSAMKeyRecord to, bool includeKey = false)
        {
            to.Id = Id;
            to.Version = Version;
            to.Name = Name;
            to.Hash = Hash.ToArray();
            if (Attributes != null) to.Attributes = Attributes;
        }

        public abstract PACSAMKeyRecord Clone(bool includeKey = false);

        public abstract byte[] PackRecord(string element = "");

        /// <summary>
        /// Generates an n-part export of this key record object
        /// </summary>
        /// <param name="parts">The objects to export the parts to</param>
        public abstract void ExportParts(PACSAMKeyRecord[] parts);

        /// <summary>
        /// Imports the key material from an n-part export into the current instance
        /// </summary>
        /// <param name="parts">The objects to import to the current instance</param>
        public abstract void ImportParts(PACSAMKeyRecord[] parts);

        public override string ToString()
        {
            return string.Format("{0:X4}: {1}", Id, Name);
        }

        public abstract bool IsInitialised();
    }
}
