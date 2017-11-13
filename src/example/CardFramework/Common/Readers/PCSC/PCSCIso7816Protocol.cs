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

#region "Namespace definitions"
using System;
using System.Collections.Generic;
using System.Text;
using CardFramework.Protocols.Iso14443A;
using CardFramework.Protocols.Iso7816;
using CardFramework.Helpers;
using System.Runtime.InteropServices;
using System.Diagnostics;
#endregion

#region "Class definitions"
namespace CardFramework.Readers.PCSC
{
    public class PCSCIso7816Protocol : Iso7816Protocol
    {
        public event EventHandler<PCSCTranscieveEventArgs> OnTranscieve;

        protected void RaiseOnTranscieve(string message)
        {
            //Debug.WriteLine(message);
            if (OnTranscieve != null) OnTranscieve(this, new PCSCTranscieveEventArgs(message));
        }

        #region "Members - Public"
        public override void Dispose()
        {
            base.Dispose();

            // Explicitly unhook all subscribed events as they will not be able to in the event of a Card Removed event
            if (OnTranscieve != null)
            {
                Delegate[] subscribers = OnTranscieve.GetInvocationList();
                foreach (Delegate s in subscribers)
                {
                    OnTranscieve -= (EventHandler<PCSCTranscieveEventArgs>)s;
                }
            }
        }

        public override RApdu Transceive(CApdu command)
        {
            IntPtr requestPci;

            switch (myCard.CommsProtocol)
            {
                case SCardProtocol.T0:
                    requestPci = PCSCApi.SCardPciT0;
                    break;
                case SCardProtocol.T1:
                    requestPci = PCSCApi.SCardPciT1;
                    break;
                default:
                    throw PCSCException.ThrowUnsupportedProtocol();
            }

            int responseLength = 1024;
            byte[] responseBuffer = new byte[responseLength];
            byte[] cmdBuffer = command.ToArray();
            PCSCResult result = NativeMethods.SCardTransmit(myCard.Handle, requestPci, cmdBuffer, cmdBuffer.Length, IntPtr.Zero, responseBuffer, ref responseLength);

            if (PCSCResult.None == result)
            {
                byte[] response = new byte[responseLength];
                Array.Copy(responseBuffer, response, responseLength);

#if DEBUG
                RaiseOnTranscieve("CAPDU> " + Converters.ByteArrayToString(cmdBuffer));
                RaiseOnTranscieve("RAPDU> " + Converters.ByteArrayToString(response));
#endif

                return RApdu.Parse(response);
            }
            else
            {
#if DEBUG
                RaiseOnTranscieve("CAPDU> " + Converters.ByteArrayToString(cmdBuffer));
                RaiseOnTranscieve("RAPDU> Error condition (HRESULT = " + EnumHelper.GetDescription(result) + ")");
#endif
                throw new PCSCException("Communications error.");
            }
        }

        #endregion

        #region "Members - Private / Protected"

        internal PCSCIso7816Protocol(byte[] atr, PCSCCard card)
        {
            // Reference the reader
            myCard = card;

            // Get the ATR value
            this.Atr = Atr.Parse(atr);

            // Map the PC/SC comms protocol to the appropriate CardFramework protocol
            switch (myCard.CommsProtocol)
            {
                case SCardProtocol.T0:
                    CommsProtocol = Iso7816CommsProtocol.T0;
                    break;

                case SCardProtocol.T1:
                    CommsProtocol = Iso7816CommsProtocol.T1;
                    break;

                case SCardProtocol.Raw:
                    CommsProtocol = Iso7816CommsProtocol.Raw;
                    break;

                default:
                    throw PCSCException.ThrowUnsupportedProtocol();
            }
        }

        #endregion

        #region "Constants / Private Declarations"

        private PCSCCard myCard;

        #endregion
    }
}
#endregion