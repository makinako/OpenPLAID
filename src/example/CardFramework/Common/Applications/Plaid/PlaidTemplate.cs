using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace CardFramework.Applications.Plaid
{
    /// <summary>
    /// Defines the personalisation settings for a DESFire EV-1 card
    /// </summary>
    [XmlRoot("Plaid")]
    [XmlType("Plaid")]
    public class PlaidTemplate
    {
        // The name of this template profile
        [XmlAttribute("name")]
        public string Name = @"";

        // The administrative key to use on a non-personalised PLAID instance
        public PlaidTemplateKeyset TransportKey = new PlaidTemplateKeyset();

        // The administrative key
        public PlaidTemplateKeyset AdminKey = new PlaidTemplateKeyset();

        // If true, the personalisation process will leave the applet in the Blocked state, which will
        // then require unblocking using an administrative command.
        public Boolean Blocked = false;

        // The list of ACS Records
        public List<PlaidTemplateACSRecord> ACSRecords = new List<PlaidTemplateACSRecord>();

        // The list of Keysets
        public List<PlaidTemplateKeyset> Keysets = new List<PlaidTemplateKeyset>();

        // The list of Keys
        public static void Save(PlaidTemplate instance, string path)
        {
            XmlSerializer x = new XmlSerializer(typeof(PlaidTemplate));
            TextWriter writer = new StreamWriter(path);
            x.Serialize(writer, instance);
            writer.Dispose();
        }

        public static PlaidTemplate Load(string path)
        {
            PlaidTemplate instance;
            // Construct an instance of the XmlSerializer with the type  
            // of object that is being deserialized.  
            XmlSerializer serialiser = new XmlSerializer(typeof(PlaidTemplate));
            // To read the file, create a FileStream.  
            FileStream fileStream = new FileStream(path, FileMode.Open);

            // Call the Deserialize method and cast to the object type.  
            instance = (PlaidTemplate)serialiser.Deserialize(fileStream);

            fileStream.Dispose();

            return instance;
        }

        /// <summary>
        /// Validate's the current instance to make sure that there are no obvious formatting errors
        /// not caught by the XML serializer
        /// </summary>
        public void Validate()
        {
            // RULE - The TransportKey element must exist and contain valid key identifiers
            if (TransportKey?.IdBytes == null || TransportKey?.SamIdBytes == null)
            {
                throw new InvalidDataException(@"RULE - The TransportKey element must exist and contain valid key identifiers");
            }

            // RULE - The AdminKey element must exist and contain valid key identifiers
            if (AdminKey?.IdBytes == null || AdminKey?.SamIdBytes == null)
            {
                throw new InvalidDataException(@"RULE - The AdminKey element must exist and contain valid key identifiers");
            }

            // RULE - There must be at least one ACSRecord element under ACSRecords
            if (ACSRecords?.Count < 1)
            {
                throw new InvalidDataException(@"RULE - There must be at least one ACSRecord element under ACSRecords");
            }

            // RULE - There must be at least one Key element under Keysets
            if (Keysets?.Count < 1)
            {
                throw new InvalidDataException(@"RULE - There must be at least one Key element under Keysets");
            }

            // RULE - The Keysets element must contain at least and at most one key that has an identifier of 0000 (KEYSET_ADMIN)
            if (Keysets.Count(k => (k.Id == PlaidApplication.KEYSET_ADMIN)) != 1)
            {
                throw new InvalidDataException(@"RULE - The Keysets element must contain at least and at most one key that has an identifier of 0000 (KEYSET_ADMIN)");
            }

            foreach (var acs in ACSRecords)
            {
                // RULE - For each ACSRecord element, it must contain a valid op_mode_id value
                if (acs.OpModeIdBytes?.Length != 2)
                {
                    throw new InvalidDataException(@"RULE - For each ACSRecord element, it must contain a valid op_mode_id value");
                }

                // RULE - For each ACSRecord element, it must contain a Data element which must be hexidecimal
                if (acs.Data == null || (!acs.Data.IsHex() && !acs.IsTemplate()))
                {
                    throw new InvalidDataException(@"RULE - For each ACSRecord element, the data element must be hexidecimal");
                }
            }

            foreach (var keyset in Keysets)
            {
                // RULE - For each Key element, it must contain a valid id and sam_id value
                if (keyset.IdBytes?.Length != 2 || keyset.SamIdBytes?.Length != 2)
                {
                    throw new InvalidDataException(@"RULE - For each Key element, it must contain a valid id and sam_id value");
                }

                // RULE - For each Key element, it must contain at least one OpModeId
                if (keyset.AccessRules.Count < 1)
                {
                    throw new InvalidDataException(@"RULE - For each Key element, it must contain at least one OpModeId");
                }

                // RULE - For each Key element, all OpModeId values must exist as an ACSRecord element once
                foreach (var op in keyset.AccessRules)
                {
                    if (ACSRecords.Count(acs => acs.OpModeIdBytes.SequenceEqual(op)) != 1)
                    {
                        throw new InvalidDataException(@"RULE - For each Key element, all OpModeId values must exist as an ACSRecord element once");
                    }
                }
            }
        }

    }
}
