using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework.Applications.PACSAM
{
    [Flags]
    public enum PACSAMKeyAttribute : ushort
    {
        None = 0,

        // This key is permitted to perform a PLAID authentication
        PLAID_AUTH = (ushort)(1 << 0),

        // This key is permitted to encrypt PLAID key value
        PLAID_KEK = (ushort)(1 << 1),

        /*
         * Key attributes (DESFIRE EV1)
         */

        // This key is permitted to generate an object MAC value
        DF_MAC = (ushort)(1 << 2),

        // This key is permitted to perform an authentication operation
        DF_AUTH = (ushort)(1 << 3),

        // This key is permitted to perform an ENCRYPT or DECRYPT operation
        DF_ENCRYPT = (ushort)(1 << 4),

        // This key is permitted to be used in a CHANGE KEY operation as the CHANGE KEY.
        DF_CHANGE_KEY = (ushort)(1 << 5),

        // This key is permitted to perform a CHANGE KEY operation as the NEW key.
        DF_CHANGEABLE = (ushort)(1 << 6),

        // This key must be diversified before use
        DF_DIV_KEY = (ushort)(1 << 7),

    }
}
