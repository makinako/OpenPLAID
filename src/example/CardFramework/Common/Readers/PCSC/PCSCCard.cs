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
using CardFramework.Protocols.Iso7816;
using System.Runtime.InteropServices;
using System.Threading;
using static CardFramework.Readers.PCSC.PCSCAttributes;

namespace CardFramework.Readers.PCSC
{
    public enum SwitchProtocolStandard
    {
        Iso14443A = 0x00,
        Iso14443B = 0x01,
        Iso15693 = 0x02,
        Felica = 0x03,
        ICodeEpcUid = 0x04,
        ICode = 0x05,
        HfEpcG2 = 0x06
    }

    public enum SwitchProtocolLayer
    {
        NoLayerSeparation = 0x00,
        Layer2 = 0x02,
        Layer3 = 0x03,
        Layer4 = 0x04,
        Iso78164 = 0x40
    }

    public class PCSCCard : Card, IDisposable
    {

        public PCSCCard(string readerName)
          : base()
        {
            myReaderName = readerName;
        }

        ~PCSCCard()
        {
            Dispose();
        }

        public bool IsConnected
        {
            get { return myHandle != IntPtr.Zero; }
        }
        public void Connect(SCardShareMode shareMode = SCardShareMode.Shared)
        {
            PCSCResult result;

            // Are we already connected?
            if (myHandle != IntPtr.Zero) return;

            // Establish a new session context for this card
            result = NativeMethods.SCardEstablishContext(SCardScope.User, IntPtr.Zero, IntPtr.Zero, out myContext);
            if (PCSCResult.None != result) throw PCSCException.ThrowByResult(result);

            // Connect to the card
            result = NativeMethods.SCardConnect(myContext, myReaderName, shareMode, DefaultRequestedProtocols, ref myHandle, ref myCommsProtocol);

            if (PCSCResult.None != result)
            {
                // Disconnect (this will gracefully handle the context release)
                Disconnect();
                throw PCSCException.ThrowByResult(result);
            }

            // Retrieve our ATR
            byte[] readerName = new byte[255];
            uint readerLen = 255;
            SCardState state = 0;
            SCardProtocol cardProtocol = 0;
            uint atrLen = NativeMethods.SCARD_ATR_LENGTH;
            byte[] atr = new byte[atrLen];

            result = NativeMethods.SCardStatus(myHandle, readerName, ref readerLen, out state, out cardProtocol, atr, ref atrLen);
            if (result != PCSCResult.None)
            {
                // Disconnect from the card
                Disconnect();
                throw PCSCException.ThrowByResult(result);
            }


            //
            // Protocol Enumeration
            // 
            try
            {
                // Add the default 7816 protocol
                Protocols.Add(new PCSCIso7816Protocol(atr, this));

                // Determine whether this card is contactless or not
                if (SupportsIso14443)
                {
                    // Replace the 7816 protocol with 14443
                    Protocols.Clear();

                    var protocol = new PCSCIso14443AProtocol(atr, this);
                    Protocols.Add(protocol);

                    // Create our OptionalCommands object
                    OptionalCommands = new PCSCOptionalCommands(protocol);

                    //
                    // HACK: Adding a PCSCMifareProtocol to all ISO14443 cards, what
                    //       we should be doing is somehow determining if this card
                    //       supports Mifare or Mifare emulation
                    //
                    Protocols.Add(new PCSCMifareProtocol(this));
                }
            }
            catch (Exception)
            {
                // Disconnect from the card
                Disconnect();
                throw PCSCException.ThrowUnsupportedProtocol();
            }
        }

        public bool SupportsIso14443
        {
            get
            {
                try
                {
                    var protocol = GetProtocol<PCSCIso7816Protocol>();
                    // Retrieve our UID
                    CApdu command = new CApdu(0xFF, 0xCA, 0, le: 00);
                    RApdu response = protocol.Transceive(command);
                    if (response.IsError) return false;
                    return true;
                }
                catch (Exception)
                {
                    // Some IFD's don't support UID retrieval
                    return false;
                }
            }
        }

        public void Reconnect(SCardDisposition initialisation)
        {
            PCSCResult result = NativeMethods.SCardReconnect(myHandle, DefaultShareMode, DefaultRequestedProtocols, initialisation, ref myCommsProtocol);

            if (result != PCSCResult.None)
            {
                // Disconnect from the card
                Disconnect();
                throw PCSCException.ThrowByResult(result);
            }
        }

        public void Disconnect(SCardDisposition disposition)
        {
            // Disconnect the card
            if (myHandle != IntPtr.Zero)
            {
                NativeMethods.SCardDisconnect(myHandle, disposition);
                myHandle = IntPtr.Zero;
            }

            // Release our context
            if (myContext != IntPtr.Zero)
            {
                NativeMethods.SCardReleaseContext(myContext);
                myContext = IntPtr.Zero;
            }
        }

        public void Disconnect()
        {
            Disconnect(SCardDisposition.UnpowerCard);
        }

        public void OmnikeyRFOff()
        {
            if (myHandle == IntPtr.Zero) throw new PCSCException("Invalid operation without an active card.");
            PCSCResult hResult;
            uint code = 0x42000000 + 3207;
            byte[] buffer = new byte[128];
            buffer[0] = 0x03;
            buffer[1] = 0x01; // Off
            uint recvBytes = 0;
            if ((hResult = NativeMethods.SCardControl(myHandle, code, buffer, 2, ref buffer, (uint)buffer.Length, ref recvBytes)) != 0x00)
            {
                throw new PCSCException("Error during 'OmnikeyRFOff' command");
            }
        }

        public void OmnikeyRFOn()
        {
            if (myHandle == IntPtr.Zero) throw new PCSCException("Invalid operation without an active card.");
            PCSCResult hResult;
            uint code = 0x42000000 + 3207;
            byte[] buffer = new byte[128];
            buffer[0] = 0x03;
            buffer[1] = 0x00; // On
            uint recvBytes = 0;
            if ((hResult = NativeMethods.SCardControl(myHandle, code, buffer, 2, ref buffer, (uint)buffer.Length, ref recvBytes)) != 0x00)
            {
                throw new PCSCException("Error during 'OmnikeyRFOn' command");
            }
        }

        public void BeginTransaction()
        {
            if (myHandle == IntPtr.Zero) throw new PCSCException("Invalid operation without an active card.");
            PCSCResult hResult;
            if ((hResult = NativeMethods.SCardBeginTransaction(myHandle)) != 0x00)
            {
                throw new PCSCException("Error during 'Begin Transaction' command");
            }
        }

        public void EndTransaction()
        {
            EndTransaction(SCardDisposition.LeaveCard);
        }

        public void EndTransaction(SCardDisposition disposition)
        {
            if (myHandle == IntPtr.Zero) throw new PCSCException("Invalid operation without an active card.");

            NativeMethods.SCardEndTransaction(myHandle, disposition);
        }

        protected void ManageSession(byte[] dataObject)
        {
            CApdu command = new CApdu();
            command.Cla = CApdu.ClaProprietary;
            command.Ins = InsSupplementalCommand;
            command.P1 = 0x00; // Always null
            command.P2 = P2ManageSession;
            command.Data = dataObject;
            command.LE = 0x00;

            Iso7816Protocol protocol = GetProtocol<Iso7816Protocol>();
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("ManageSession");
            }
        }

        public void SwitchProtocol(SwitchProtocolStandard standard, SwitchProtocolLayer layer)
        {
            const byte DataLength = 4;

            // Construct the data object
            byte[] data = new byte[DataLength];
            data[0] = TagSwitchProtocol;
            data[1] = 0x02; // Static length for data object
            data[2] = (byte)standard;
            data[3] = (byte)layer;

            CApdu command = new CApdu();
            command.Cla = CApdu.ClaProprietary;
            command.Ins = InsSupplementalCommand;
            command.P1 = 0x00; // Always null
            command.P2 = P2SwitchProtocol;
            command.Data = data;

            Iso7816Protocol protocol = GetProtocol<Iso7816Protocol>();
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("SwitchProtocol");
            }
        }

        public void StartTransparentSession()
        {
            const int dataLength = 2;

            byte[] data = new byte[dataLength];
            data[0] = TagStartTransparentSession;
            data[1] = 0x00;

            ManageSession(data);
        }

        public void EndTransparentSession()
        {
            const int dataLength = 2;

            byte[] data = new byte[dataLength];
            data[0] = TagEndTransparentSession;
            data[1] = 0x00;

            ManageSession(data);
        }
        
        public void TurnOffRfField()
        {
            const int dataLength = 2;

            byte[] data = new byte[dataLength];
            data[0] = TagTurnOffRf;
            data[1] = 0x00;

            ManageSession(data);
        }

        public void TurnOnRfField()
        {
            const int dataLength = 2;

            byte[] data = new byte[dataLength];
            data[0] = TagTurnOnRf;
            data[1] = 0x00;

            ManageSession(data);
        }


        internal IntPtr Handle
        {
            get { return myHandle; }
        }

        internal SCardProtocol CommsProtocol
        {
            get { return myCommsProtocol; }
        }

        /// <summary>
        /// Contains the card attributes (TODO: PC/SC doc ref)
        /// </summary>
        public PCSCAttributes Attributes { get; private set; }

        /// <summary>
        /// Contains the 'OPTIONAL' command set (TODO: PC/SC doc ref)
        /// </summary>
        public PCSCOptionalCommands OptionalCommands { get; private set; }

        /// <summary>
        /// Internal reference to the PCSC card handle
        /// </summary>
        protected IntPtr myHandle;

        /// <summary>
        /// Dedicated PC/SC context for this card
        /// </summary>
        protected IntPtr myContext;

        /// <summary>
        /// Internal PC/SC protocol identifier
        /// </summary>
        protected SCardProtocol myCommsProtocol;

        /// <summary>
        /// Reference to our parent reader by it's PC/SC name
        /// </summary>
        protected string myReaderName;

        public const SCardShareMode DefaultShareMode = SCardShareMode.Shared;
        public const SCardProtocol DefaultRequestedProtocols = SCardProtocol.Any;

        public const byte InsSupplementalCommand = 0xC2;

        public const byte P2ManageSession = 0x00;
        public const byte P2TransparentExchange = 0x01;
        public const byte P2SwitchProtocol = 0x02;

        public const byte TagVersion = 0x80;
        public const byte TagStartTransparentSession = 0x81;
        public const byte TagEndTransparentSession = 0x82;
        public const byte TagTurnOffRf = 0x83;
        public const byte TagTurnOnRf = 0x84;

        public const byte TagSwitchProtocol = 0x8F;

        public override void Dispose()
        {
            base.Dispose();

            // Disconnect the card
            Disconnect();
        }
    }
}
