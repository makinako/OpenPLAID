#region "Copyright"
/******************************************************************************************
 Copyright (C) 2012 Kim O'Sullivan (kim@makina.com.au)

 Permission is hereby granted, free of charge, to any person obtaining a copy of 
 this software and associated documentation files (the "Software"), to deal in the 
 Software without restriction, including without limitation the rights to use, copy, 
 modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 and to permit persons to whom the Software is furnished to do so, subject to the 
 following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies 
 or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT 
 OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************************/
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using CardFramework.Helpers;

namespace CardFramework.Readers.PCSC
{
    public class PCSCAttributes
    {
        internal PCSCAttributes(PCSCCard card)
        {
            myCard = card;
        }

        internal byte[] GetAttribute(uint attribute)
        {
            PCSCResult result = 0;
            IntPtr len = IntPtr.Zero;

            // Get the length required
            result = NativeMethods.SCardGetAttrib(myCard.Handle, attribute, null, ref len);
            if (result != PCSCResult.None) throw PCSCException.ThrowByResult(result);

            // Get the value
            byte[] buffer = new byte[len.ToInt32()];
            result = NativeMethods.SCardGetAttrib(myCard.Handle, attribute, buffer, ref len);
            if (result != PCSCResult.None) throw PCSCException.ThrowByResult(result);

            return buffer;
        }


        [Description(@"$$")]
        private const uint SCARD_ATTR_USER_AUTH_INPUT_DEVICE = 0x00050142;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_W = 0x00080206;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ICC_TYPE_PER_ATR = 0x00090304;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ESC_CANCEL = 0x0007A003;

        [Description(@"$$")]
        private const uint SCARD_ATTR_MAX_CLK = 0x00030122;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CHANNEL_ID = 0x00020110;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_PROTOCOL_TYPE = 0x00080201;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_N = 0x00080205;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_BWT = 0x00080209;

        [Description(@"$$")]
        private const uint SCARD_ATTR_EXTENDED_BWT = 0x0008020C;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ICC_INTERFACE_STATUS = 0x00090301;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ESC_AUTHREQUEST = 0x0007A005;

        [Description(@"$$")]
        private const uint SCARD_ATTR_SUPRESS_T1_IFS_REQUEST = 0x7FFF0007;

        [Description(@"$$")]
        private const uint SCARD_ATTR_MAX_IFSD = 0x00030125;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_D = 0x00080204;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_CWT = 0x0008020A;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_IO_STATE = 0x00090302;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_FRIENDLY_NAME_A = 0x7FFF0003;

        [Description(@"$$")]
        private const uint SCARD_ATTR_SYNC_PROTOCOL_TYPES = 0x00030126;

        [Description(@"$$")]
        private const uint SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE = 0x00050140;

        [Description(@"$$")]
        private const uint SCARD_ATTR_MAXINPUT = 0x0007A007;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_FRIENDLY_NAME_W = 0x7FFF0005;

        [Description(@"$$")]
        private const uint SCARD_ATTR_VENDOR_IFD_TYPE = 0x00010101;

        [Description(@"$$")]
        private const uint SCARD_ATTR_VENDOR_IFD_VERSION = 0x00010102;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_CLK = 0x00080202;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_F = 0x00080203;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ICC_PRESENCE = 0x00090300;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_UNIT = 0x7FFF0001;

        [Description(@"$$")]
        private const uint SCARD_ATTR_VENDOR_IFD_SERIAL_NO = 0x00010103;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CHARACTERISTICS = 0x00060150;
        private const uint SCARD_ATTR_CHARACTERISTICS_NONE = 0x00000000;
        private const uint SCARD_ATTR_CHARACTERISTICS_SWALLOWING = 0x00000001;
        private const uint SCARD_ATTR_CHARACTERISTICS_EJECTING = 0x00000002;
        private const uint SCARD_ATTR_CHARACTERISTICS_CAPTURE = 0x00000004;
        private const uint SCARD_ATTR_CHARACTERISTICS_CONTACTLESS = 0x00000008;


        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_EBC_ENCODING = 0x0008020B;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_IN_USE = 0x7FFF0002;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_SYSTEM_NAME = 0x7FFF0004;

        [Description(@"$$")]
        private const uint SCARD_ATTR_VENDOR_NAME = 0x00010100;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEFAULT_DATA_RATE = 0x00030123;


        [Description(@"Answer to reset (ATR) string")]
        private const uint SCARD_ATTR_ATR_STRING = 0x00090303;

        [Description(@"$$")]
        private const uint SCARD_ATTR_MAX_DATA_RATE = 0x00030124;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_SYSTEM_NAME_A = 0x7FFF0004;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_SYSTEM_NAME_W = 0x7FFF0006;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ASYNC_PROTOCOL_TYPES = 0x00030120;
        private const uint SCARD_ATTR_ASYNC_PROTOCOL_TYPES_T0 = 0x00000001;
        private const uint SCARD_ATTR_ASYNC_PROTOCOL_TYPES_T1 = 0x00000002;
        private const uint SCARD_ATTR_ASYNC_PROTOCOL_TYPES_TCL = 0x00010000;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEFAULT_CLK = 0x00030121;

        [Description(@"$$")]
        private const uint SCARD_ATTR_POWER_MGMT_SUPPORT = 0x00040131;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_IFSC = 0x00080207;

        [Description(@"$$")]
        private const uint SCARD_ATTR_CURRENT_IFSD = 0x00080208;

        [Description(@"$$")]
        private const uint SCARD_ATTR_ESC_RESET = 0x0007A000;

        [Description(@"$$")]
        private const uint SCARD_ATTR_DEVICE_FRIENDLY_NAME = 0x7FFF0003;

        // Non-PCSC property to return whether this IFD is connected over the conactless interface
        public bool IfdExIsIso144443
        {
            get
            {
                bool result = false;
                var x = GetAttributeUInt32(SCARD_ATTR_ASYNC_PROTOCOL_TYPES);
                try
                {
                    if (IfdDefaultClock == 13560) result = true;
                }
                catch (Exception)
                {
                }

                try
                {
                    if (IfdSupportsTCL) result = true;
                }
                catch (Exception)
                {
                }

                // Finally, check against a list of known ISO-14443 generated ATR values
                if (IccAtr.SequenceEqual(new byte[] { 0x3B, 0x80, 0x80, 0x01, 0x01 })) return true;
                if (IccAtr.SequenceEqual(new byte[] { 0x3B, 0x81, 0x80, 0x01, 0x80, 0x80 })) return true;

                return result;
            }
        }

        public bool IfdSupportsT0
        {
            get
            {
                return ((GetAttributeUInt32(SCARD_ATTR_ASYNC_PROTOCOL_TYPES) & SCARD_ATTR_ASYNC_PROTOCOL_TYPES_T0) != 0);
            }
        }

        public bool IfdSupportsT1
        {
            get
            {
                return ((GetAttributeUInt32(SCARD_ATTR_ASYNC_PROTOCOL_TYPES) & SCARD_ATTR_ASYNC_PROTOCOL_TYPES_T1) != 0);
            }
        }

        public bool IfdSupportsTCL
        {
            get
            {
                return ((GetAttributeUInt32(SCARD_ATTR_ASYNC_PROTOCOL_TYPES) & SCARD_ATTR_ASYNC_PROTOCOL_TYPES_TCL) != 0);
            }
        }

        public bool IfdHasCardSwallowingMechanism
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_CHARACTERISTICS) == SCARD_ATTR_CHARACTERISTICS_SWALLOWING);
            }
        }

        public bool IfdHasCardEjectionMechanism
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_CHARACTERISTICS) == SCARD_ATTR_CHARACTERISTICS_EJECTING);
            }
        }

        public bool IfdHasCardCaptureMechanism
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_CHARACTERISTICS) == SCARD_ATTR_CHARACTERISTICS_CAPTURE);
            }
        }

        public bool IfdHasContactless
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_CHARACTERISTICS) == SCARD_ATTR_CHARACTERISTICS_CONTACTLESS);
            }
        }

        public uint IfdDefaultClock
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_DEFAULT_CLK));
            }
        }


        public uint IfdMaxClock
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_MAX_CLK));
            }
        }


        public uint IfdDefaultDataRate
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_DEFAULT_DATA_RATE));
            }
        }


        public uint IfdMaxDataRate
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_MAX_DATA_RATE));
            }
        }

        public uint IfdMaxIfsd
        {
            get
            {
                return (GetAttributeUInt32(SCARD_ATTR_MAX_IFSD));
            }
        }

        [Flags]
        public enum IccPresenceStatus
        {
            NotPresent = 0x00,
            PresentNotSwallowed = 0x01,
            Present = 0x02,
            Confiscated = 0x04
        }


        public IccPresenceStatus IccPresence
        {
            get
            {
                return (IccPresenceStatus)(GetAttributeByte(SCARD_ATTR_ICC_PRESENCE));
            }
        }

        public bool IccIsContactActive
        {
            get
            {
                return (GetAttributeByte(SCARD_ATTR_ICC_INTERFACE_STATUS) == 1);
            }
        }

        public byte[] IccAtr
        {
            get
            {
                return GetAttribute(SCARD_ATTR_ATR_STRING);
            }
        }

        public string IccAtrString
        {
            get
            {
                return GetAttributeString(SCARD_ATTR_ATR_STRING);
            }
        }

        public enum IccTypes
        {
            Unknown = 0x00,
            Iso7816Asynchronous = 0x01,
            Iso7816Synchronous = 0x02,
            Iso781610Synchronous1 = 0x03,
            Iso781610Synchronous2 = 0x04,
            Iso14443A = 0x05,
            Iso14443B = 0x06,
            Iso15963 = 0x07,
        }

        public IccTypes IccType
        {
            get
            {

                IccTypes type;
                try
                {
                    type = (IccTypes)GetAttributeByte(SCARD_ATTR_ICC_TYPE_PER_ATR);
                }
                catch
                {
                    // Set to default
                    type = IccTypes.Iso7816Synchronous;
                }

                return type;
            }
        }

        private string GetAttributeString(uint attribute)
        {
            return Converters.ByteArrayToString(GetAttribute(attribute));
        }

        private uint GetAttributeUInt32(uint attribute)
        {
            byte[] buffer = GetAttribute(attribute);

            if (buffer.Length != 4) throw new PCSCException(@"Unexpected attribute response length");

            return BitConverter.ToUInt32(buffer, 0);
        }

        private uint GetAttributeByte(uint attribute)
        {
            byte[] buffer = GetAttribute(attribute);

            if (buffer.Length != 1) throw new PCSCException(@"Unexpected attribute response length");

            return buffer[0];
        }

        private PCSCCard myCard;
    }
}
