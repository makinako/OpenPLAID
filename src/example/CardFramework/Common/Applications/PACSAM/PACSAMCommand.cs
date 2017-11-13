using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework.Applications.PACSAM
{
    public enum PACSAMCommand
    {
        Undefined = 0x00,

        SetData = 0x10,
        GetStatus = 0x11,
        VerifyPin = 0x12,
        ResetAuth = 0x13,
        Activate = 0x14,
        Terminate = 0x15,
        LoadKey = 0x16,
        ReadNextKey = 0x17,

        // Applet commands - DESFire EV-1
        EV1Auth0 = 0x21,
        EV1Auth1 = 0x22,
        EV1ChangeKey = 0x23,
        EV1GenerateMac = 0x24,
        EV1verifyMac = 0x25,
        EV1Encipher = 0x26,
        EV1Decipher = 0x27,
        EV1UpdateIV = 0x28,
        EV1SetDivData = 0x29,

        // Applet commands - PLAID
        PlaidLoadFAKey = 0x81,
        PlaidSetData = 0x82,
        PlaidInitialAuth = 0x87,
        PlaidFinalAuth = 0x86
    }
}
