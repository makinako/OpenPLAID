using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CardFramework.Applications.Iso7816
{
    public class Iso7816Exception : ApplicationException
    {
        public ushort SW12;

        public Iso7816Exception()
        {
            BuildErrorCodes();
            Source = @"No source";
        }

        public Iso7816Exception(ushort sw12)
        {
            BuildErrorCodes();
            SW12 = sw12;
            Source = @"No source";
        }

        public Iso7816Exception(ushort sw12, string source)
        {
            BuildErrorCodes();
            Source = source;
            SW12 = sw12;
        }

        public override string Message
        {
            get
            {
                if (myErrors.ContainsKey(SW12))
                {
                    string msg = string.Format("{0}: {1} (SW={2:X4})", Source, myErrors[SW12], SW12);
                    return msg;
                }
                else
                {
                    string msg = string.Format("{0}: Unspecified error (SW={1:X4})", Source, SW12);
                    return msg;
                }
            }
        }

        private static void BuildErrorCodes()
        {
            if (myErrors != null) return;

            myErrors = new Dictionary<ushort, string>();
            myErrors.Add(0x9000, "No error");
            myErrors.Add(0x6200, "Warning - No information");
            myErrors.Add(0x6281, "Warning - Part of returned data may be corrupted");
            myErrors.Add(0x6282, "Warning - End of file or record reached before reading N(e) bytes");
            myErrors.Add(0x6283, "Warning - Selected file deactivated");
            myErrors.Add(0x6284, "Warning - File control information not formatted according to 5.3.3");
            myErrors.Add(0x6285, "Warning - Selected file in termination state");
            myErrors.Add(0x6286, "Warning - No input data available from a sensor on the card");
            myErrors.Add(0x6300, "Warning - No information");
            myErrors.Add(0x6381, "Warning - File filled up by the last write");
            myErrors.Add(0x6400, "Error - Execution error");
            myErrors.Add(0x6401, "Error - Immediate response required by the card");
            myErrors.Add(0x6500, "Error - No information given");
            myErrors.Add(0x6581, "Error - Memory failure");
            myErrors.Add(0x6800, "Error - No information given");
            myErrors.Add(0x6881, "Error - Logical channel not supported");
            myErrors.Add(0x6882, "Error - Secure messaging not supported");
            myErrors.Add(0x6883, "Error - Last command of the chain expected");
            myErrors.Add(0x6884, "Error - Command chaining not supported");
            myErrors.Add(0x6900, "Error - No information given");
            myErrors.Add(0x6981, "Error - Command incompatible with file structure");
            myErrors.Add(0x6982, "Error - Security status not satisfied");
            myErrors.Add(0x6983, "Error - Authentication method blocked");
            myErrors.Add(0x6984, "Error - Reference data not usable");
            myErrors.Add(0x6985, "Error - Conditions of use not satisfied");
            myErrors.Add(0x6986, "Error - Command not allowed");
            myErrors.Add(0x6987, "Error - Expected secure messaging data objects missing");
            myErrors.Add(0x6988, "Error - Incorrect secure messaging data objects");
            myErrors.Add(0x6A00, "Error - No information given");
            myErrors.Add(0x6A80, "Error - Incorrect parameters in the command data field");
            myErrors.Add(0x6A81, "Error - Function not supported");
            myErrors.Add(0x6A82, "Error - File or application not found");
            myErrors.Add(0x6A83, "Error - Record not found");
            myErrors.Add(0x6A84, "Error - Not enough memory space in the file");
            myErrors.Add(0x6A85, "Error - N(c) inconsistent with TLV structure");
            myErrors.Add(0x6A86, "Error - Incorrect parameters P1-P2");
            myErrors.Add(0x6A87, "Error - N(c) inconsistent with parameters P1-P2");
            myErrors.Add(0x6A88, "Error - Referenced data or reference data not found");
            myErrors.Add(0x6A89, "Error - File already exists");
            myErrors.Add(0x6A8A, "Error - DF name already exists");

        }

        protected static Dictionary<ushort, string> myErrors = null;




        // Mnemonics for the SW1,SW2 error codes

        /**
         * Response status : No Error = (public const short)0x9000
         */
        public const ushort SW_OK = (ushort)0x9000;

        /**
         * Response status : Response bytes remaining = 0x6100
         */
        public const ushort SW_BYTES_REMAINING_00 = 0x6100;

        /**
         * Response status : Wrong length = 0x6700
         */
        public const ushort SW_WRONG_LENGTH = 0x6700;

        /**
         * Response status : Security condition not satisfied = 0x6982
         */
        public const ushort SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;

        /**
         * Response status : File invalid = 0x6983
         */
        public const ushort SW_FILE_INVALID = 0x6983;

        /**
         * Response status : Data invalid = 0x6984
         */
        public const ushort SW_DATA_INVALID = 0x6984;

        /**
         * Response status : Conditions of use not satisfied = 0x6985
         */
        public const ushort SW_CONDITIONS_NOT_SATISFIED = 0x6985;

        /**
         * Response status : Command not allowed (no current EF) = 0x6986
         */
        public const ushort SW_COMMAND_NOT_ALLOWED = 0x6986;

        /**
         * Response status : Applet selection failed = 0x6999;
         */
        public const ushort SW_APPLET_SELECT_FAILED = 0x6999;

        /**
         * Response status : Wrong data = 0x6A80
         */
        public const ushort SW_WRONG_DATA = 0x6A80;

        /**
         * Response status : Function not supported = 0x6A81
         */
        public const ushort SW_FUNC_NOT_SUPPORTED = 0x6A81;

        /**
         * Response status : File not found = 0x6A82
         */
        public const ushort SW_FILE_NOT_FOUND = 0x6A82;

        /**
         * Response status : Record not found = 0x6A83
         */
        public const ushort SW_RECORD_NOT_FOUND = 0x6A83;

        /**
         * Response status : Incorrect parameters (P1,P2) = 0x6A86
         */
        public const ushort SW_INCORRECT_P1P2 = 0x6A86;

        /**
         * Response status : Incorrect parameters (P1,P2) = 0x6B00
         */
        public const ushort SW_WRONG_P1P2 = 0x6B00;

        /**
         * Response status : Correct Expected Length (Le) = 0x6C00
         */
        public const ushort SW_CORRECT_LENGTH_00 = 0x6C00;

        /**
         * Response status : INS value not supported = 0x6D00
         */
        public const ushort SW_INS_NOT_SUPPORTED = 0x6D00;

        /**
         * Response status : CLA value not supported = 0x6E00
         */
        public const ushort SW_CLA_NOT_SUPPORTED = 0x6E00;

        /**
         * Response status : No precise diagnosis = 0x6F00
         */
        public const ushort SW_UNKNOWN = 0x6F00;

        /**
         * Response status : Not enough memory space in the file  = 0x6A84
         */
        public const ushort SW_FILE_FULL = 0x6A84;

        // Logical channel errors

        /**
         * Response status : Card does not support the operation on the specified logical channel  = 0x6881
         */
        public const ushort SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881;

        /**
         * Response status : Card does not support secure messaging = 0x6882
         */
        public const ushort SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882;

        /**
         * Response status : Warning, card state unchanged  = 0x6200
         */
        public const ushort SW_WARNING_STATE_UNCHANGED = 0x6200;

        /**
         * Response status : Last command in chain expected = 0x6883
         */
        public const ushort SW_LAST_COMMAND_EXPECTED = 0x6883;

        /**
         * Response status : Command chaining not supported = 0x6884
         */
        public const ushort SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884;

    }
}
