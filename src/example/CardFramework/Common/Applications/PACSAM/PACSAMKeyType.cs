using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework.Applications.PACSAM
{
    /// <summary>
    /// Defines the key type for this key
    /// </summary>
    /// <remarks>The values are based on the constants defined in javacard.security.KeyBuilder</remarks>
    public enum PACSAMKeyType
    {
        Undefined = 0,

        DES = 3,
        AES = 15,
        RSACrtPrivate = 6,
        RSAPublic = 4,

        // Non-standard key type for our own PLAID implementation
        PLAID = 0x90,
    }
}
