using CardFramework.Helpers;
using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CardFramework.Applications.Plaid
{
    public abstract class PlaidRequest
    {
        //
        // PLAID administrative constants (non-ISO)
        //

        // Operations
        public const byte OP_ACTIVATE = 1;
        public const byte OP_BLOCK = 2;
        public const byte OP_UNBLOCK = 3;
        public const byte OP_TERMINATE = 4;
        public const byte OP_KEY_CREATE = 5;
        public const byte OP_KEY_DELETE = 6;
        public const byte OP_KEY_DELETE_ALL = 7;
        public const byte OP_ACSR_CREATE = 8;
        public const byte OP_ACSR_DELETE = 9;
        public const byte OP_ACSR_DELETE_ALL = 10;
        public const byte OP_PAYLOAD_CREATE = 11;
        public const byte OP_PAYLOAD_DELETE = 12;
        public const byte OP_PAYLOAD_DELETE_ALL = 13;
        public const byte OP_FACTORY_RESET = 127;

        // Lengths
        public const short LENGTH_OP_HASH = 16;
        public const short LENGTH_GETKEY_HASH = 16;

        // Tags - General
        public const byte TAG_SAMID = 30;

        // Tags - Keyset
        public const byte TAG_KEYSET_IAMODULUS = 11;
        public const byte TAG_KEYSET_IAEXPONENT = 12;
        public const byte TAG_KEYSET_FAKEY = 13;

        // Tags - Parameters
        // NOTE: Duplicates are ok here because they are unique to each command
        public const byte TAG_PARAM_ID = 1;
        public const byte TAG_PARAM_KEY = 2;
        public const byte TAG_PARAM_DATA = 2;
        public const byte TAG_PARAM_RULES = 3;

        public byte[] Encode()
        {
            var stream = new MemoryStream();
            Asn1Generator sequence = new DerSequenceGenerator(stream);

            // Counter (We don't populate the value, the PACSAM does)
            sequence.AddObject(new DerInteger(0));

            // Operation
            sequence.AddObject(new DerEnumerated(OperationCode));

            // Request Parameters (OPTIONAL)
            EncodeParameters(sequence);

            // Done
            sequence.Close();
            return stream.ToArray();
        }

        protected virtual void EncodeParameters(Asn1Generator generator)
        {
            // By default, no parameters
        }

        protected abstract short OperationCode { get; }
    }


    public class ActivateRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_ACTIVATE; }
        }
    }

    public class BlockRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_BLOCK; }
        }
    }

    public class UnblockRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_UNBLOCK; }
        }
    }

    public class TerminateRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_TERMINATE; }
        }
    }

    public class FactoryResetRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_FACTORY_RESET; }
        }
    }

    public class KeyCreateRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_KEY_CREATE; }
        }

        public short Id { get; set; }
        public short SamId { get; set; }
        public List<byte[]> Rules { get; private set; } = new List<byte[]>();

        protected override void EncodeParameters(Asn1Generator generator)
        {
            // Id
            var id = new DerApplicationSpecific(TAG_PARAM_ID, BinaryParser.ConvertInt16(Id, ByteEndianess.BigEndian));

            // Keyset - IA Modulus
            var iaModulus = new DerApplicationSpecific(TAG_KEYSET_IAMODULUS, new byte[PlaidApplication.LENGTH_KEY_RSA]);

            // Keyset - IA Exponent
            var iaExponent = new DerApplicationSpecific(TAG_KEYSET_IAEXPONENT, new byte[PlaidApplication.LENGTH_PUBLIC_EXPONENT]);

            // Keyset - FAKey
            var faKey = new DerApplicationSpecific(TAG_KEYSET_FAKEY, new byte[PlaidApplication.LENGTH_KEY_AES]);

            // Rules
            List<DerOctetString> rules = new List<DerOctetString>();
            foreach (var rule in Rules) rules.Add(new DerOctetString(rule));
            
            // Parameters (Choice)
            var parameters = new DerSequenceGenerator(generator.GetRawOutputStream(), OP_KEY_CREATE, false);
            parameters.AddObject(id);
            parameters.AddObject(new DerApplicationSpecific(TAG_PARAM_KEY, new Asn1EncodableVector(iaModulus, iaExponent, faKey)));
            parameters.AddObject(new DerApplicationSpecific(TAG_PARAM_RULES, new Asn1EncodableVector(rules.ToArray())));
            parameters.Close();

            // SamId
            var samId = new DerApplicationSpecific(TAG_SAMID, BinaryParser.ConvertInt16(SamId, ByteEndianess.BigEndian));
            generator.AddObject(samId);
        }
    }

    public class KeyDeleteRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_KEY_DELETE; }
        }

        public short Id { get; set; }

        protected override void EncodeParameters(Asn1Generator generator)
        {
            // Id
            generator.AddObject(new DerApplicationSpecific(TAG_PARAM_ID, BinaryParser.ConvertInt16(Id, ByteEndianess.BigEndian)));
        }
    }

    public class KeyDeleteAllRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_KEY_DELETE_ALL; }
        }
    }

    public class AcsrCreateRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_ACSR_CREATE; }
        }

        public short Id { get; set; }
        public byte[] Data { get; set; }

        protected override void EncodeParameters(Asn1Generator generator)
        {
            // Id
            generator.AddObject(new DerApplicationSpecific(TAG_PARAM_ID, BinaryParser.ConvertInt16(Id, ByteEndianess.BigEndian)));

            // Data
            generator.AddObject(new DerApplicationSpecific(TAG_PARAM_DATA, Data));
        }
    }

    public class AcsrDeleteRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_ACSR_DELETE; }
        }

        public short Id { get; set; }

        protected override void EncodeParameters(Asn1Generator generator)
        {
            // Id
            generator.AddObject(new DerApplicationSpecific(TAG_PARAM_ID, BinaryParser.ConvertInt16(Id, ByteEndianess.BigEndian)));
        }
    }

    public class AcsrDeleteAllRequest : PlaidRequest
    {
        protected override short OperationCode
        {
            get { return OP_ACSR_DELETE_ALL; }
        }
    }
}
