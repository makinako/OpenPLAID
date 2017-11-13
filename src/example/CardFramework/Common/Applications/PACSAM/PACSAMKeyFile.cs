using CardFramework.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Serialization;

namespace CardFramework.Applications.PACSAM
{
    [XmlType("KeyFile")]
    [XmlRoot("KeyFile")]
    public class PACSAMKeyFile : PACSAMKeyRecord
    {
        public PACSAMKeyFile(PACSAMKeyFile copyObject)
        {
            copyObject.CopyTo(this);
        }

        public PACSAMKeyFile()
        {
        }

        public int? Part = null;
        public int? PartCount = null;

        [XmlElement(DataType = "hexBinary")]
        public byte[] SystemDiversifier = new byte[0];

        // The list of applications
        [XmlArrayItem("KeyRecord")]
        public List<PACSAMKeyRecord> Records = new List<PACSAMKeyRecord>();


        public PACSAMKeyRecord this[int index]
        {
            get
            {
                return Records[index];
            }
        }

        public PACSAMKeyRecord this[string name]
        {
            get
            {
                return Records.First(item => item.Name.Equals(name, StringComparison.CurrentCultureIgnoreCase));
            }
        }

        public static void Save(PACSAMKeyFile instance, string path, bool recomputeHashes = false)
        {
            // Recompute the hashes if required
            if (recomputeHashes)
            {
                instance.UpdateHash();
                foreach (PACSAMKeyRecord r in instance.Records) r.UpdateHash();
            }

            Serialiser<PACSAMKeyFile>.Save(path, instance);
        }

        public static PACSAMKeyFile Load(string path, bool ignoreHash = false)
        {
            PACSAMKeyFile instance = Serialiser<PACSAMKeyFile>.Load(path);

            // Verify the hashes
            if (!ignoreHash && !instance.VerifyHash())
            {
                throw new InvalidDataException("Hash verification failed.");
            }

            return instance;
        }

        public override byte[] GetHashInputData()
        {
            var data = new BinaryParser();

            // Get the basic key record data
            data?.WriteBytes(base.GetHashInputData());

            foreach (PACSAMKeyRecord r in Records)
            {
                byte[] hash = r.GetHashInputData();
                data.WriteBytes(hash, 0, hash.Length);
            }

            return data.ToArray();
        }

        public override byte[] PackRecord(string element = "")
        {
            throw new InvalidOperationException();
        }

        public override void Generate()
        {
            foreach (PACSAMKeyRecord r in Records) r.Generate();
        }


        public override void CopyTo(PACSAMKeyRecord to, bool includeKey = false)
        {
            base.CopyTo(to);

            (to as PACSAMKeyFile).Part = Part;
            (to as PACSAMKeyFile).PartCount = PartCount;
            (to as PACSAMKeyFile).SystemDiversifier = SystemDiversifier.ToArray();

            // Overwrite the attribute field to None (doesn't apply)
            (to as PACSAMKeyFile).Attributes = PACSAMKeyAttribute.None;
        }

        public override PACSAMKeyRecord Clone(bool includeKey = false)
        {
            PACSAMKeyFile instance = new PACSAMKeyFile();
            CopyTo(instance, includeKey);

            foreach (var record in Records)
            {
                instance.Records.Add(record.Clone(includeKey));
            }

            return instance;
        }

        public override void ExportParts(params PACSAMKeyRecord[] parts)
        {
            // There must be at least 3 or more parts
            if (parts.Length < 3) throw new ArgumentException(@"ExportParts: There must be at 3 or more parts to export to!");

            // Create the resulting keyfile parts
            for (int i = 0; i < parts.Length; i++)
            {
                // Generate the part
                parts[i] = new PACSAMKeyFile(this);
            }

            // Export each key
            foreach (var record in Records)
            {
                PACSAMKeyRecord[] keyParts = new PACSAMKeyRecord[parts.Length];

                // Generate the key parts
                record.ExportParts(keyParts);
                for (int i = 0; i < parts.Length; i++)
                {
                    var pI = (parts[i] as PACSAMKeyFile);
                    pI.Records.Add(keyParts[i]);
                }
            }

            // Export the SystemIdentifier
            for (int i = 1; i < parts.Length; i++)
            {
                var pI = (parts[i] as PACSAMKeyFile);
                var p0 = (parts[0] as PACSAMKeyFile);

                pI.SystemDiversifier = Crypto.CreateRandomEntropy(SystemDiversifier.Length);
                p0.SystemDiversifier = Crypto.XorArray(p0.SystemDiversifier, pI.SystemDiversifier);
            }

            // Set the Part and PartCount values
            for (int i = 0; i < parts.Length; i++)
            {
                (parts[i] as PACSAMKeyFile).Part = (i + 1);
                (parts[i] as PACSAMKeyFile).PartCount = parts.Length;
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

            // Copy the basic information from the first part
            parts[0].CopyTo(this);

            var p0 = (parts[0] as PACSAMKeyFile);
            for (int i = 0; i < p0.Records.Count; i++)
            {
                PACSAMKeyRecord record = p0.Records[i].Clone();
                PACSAMKeyRecord[] keyParts = new PACSAMKeyRecord[parts.Length];

                for (int j = 0; j < parts.Length; j++)
                {
                    keyParts[j] = (parts[j] as PACSAMKeyFile).Records[i];

                    if (!keyParts[j].Name.Equals(record.Name))
                    {
                        throw new InvalidDataException(@"Key name mismatch while importing '" + record.Name + "' (possibly out of order).");
                    }
                }

                // Import
                try
                {
                    record.ImportParts(keyParts);
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException(ex.Message + " (Key Name: " + record.Name + ")");
                }

                // Add
                Records.Add(record);
            }

            // Import the SystemIdentifier
            for (int i = 1; i < parts.Length; i++)
            {
                var pI = (parts[i] as PACSAMKeyFile);
                SystemDiversifier = Crypto.XorArray(SystemDiversifier, pI.SystemDiversifier);
            }
        }

        public override bool IsInitialised()
        {
            return (Records.Count > 0);
        }
    }
}
