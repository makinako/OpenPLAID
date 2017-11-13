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
using System.Runtime.InteropServices;
using System.ComponentModel;
#endregion

#region "Class definitions"
namespace CardFramework.Readers.PCSC
{
    internal static class PCSCApi
    {
        private static Object thisLock = new Object();

        public static IntPtr GetGlobalPci(SCardProtocol protocol)
        {
            string globalPath = @"";

            switch (protocol)
            {
                case SCardProtocol.T0:
                    globalPath = "g_rgSCardT0Pci";
                    break;

                case SCardProtocol.T1:
                    globalPath = "g_rgSCardT1Pci";
                    break;

                case SCardProtocol.Raw:
                    globalPath = "g_rgSCardRawPci";
                    break;

                default:
                    throw PCSCException.ThrowByResult(PCSCResult.ProtocolMismatch);
            }

            IntPtr handle = NativeMethods.LoadLibrary("Winscard.dll");
            IntPtr pci = NativeMethods.GetProcAddress(handle, globalPath);
            NativeMethods.FreeLibrary(handle);
            return pci;
        }

        public static readonly IntPtr SCardPciT0 = GetGlobalPci(SCardProtocol.T0);
        public static readonly IntPtr SCardPciT1 = GetGlobalPci(SCardProtocol.T1);

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        /// <summary>
        /// Wait indefinitely for a status change.
        /// </summary>
        public const uint INFINITE = unchecked((uint)0xFFFFFFFF);
        #endregion

    }

    internal static class NativeMethods
    {
        #region "Members - Public"

        /*
         * Kernel functions
         */
        [DllImport("kernel32.dll")]
        public extern static IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll")]
        public extern static void FreeLibrary(IntPtr handle);

        [DllImport("kernel32.dll")]
        public extern static IntPtr GetProcAddress(IntPtr handle, string procName);

        /*
         * Smart Card PCSC dll functions (Windows PCSC subsystem)
         */
        [DllImport("winscard.dll")]
        public static extern PCSCResult SCardEstablishContext(SCardScope dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out IntPtr phContext);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardReleaseContext(IntPtr phContext);

        [DllImport("winscard.dll", CharSet = CharSet.Auto)]
        public static extern PCSCResult SCardGetStatusChange(IntPtr hContext, uint dwTimeout, [In, Out] SCARD_READERSTATE[] rgReaderStates, int cReaders);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardIsValidContext(IntPtr phContext);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardCancel(IntPtr hContext);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardConnect(IntPtr hContext, string cReaderName,
            SCardShareMode dwShareMode, SCardProtocol dwPrefProtocol, ref IntPtr phCard, ref SCardProtocol ActiveProtocol);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardStatus(IntPtr hCard, byte[] readerName, ref uint dwReaderLen, out SCardState state, out SCardProtocol protocol, byte[] atr, ref uint atrLen);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardControl(IntPtr hCard, uint dwControlCode, byte[] lpInBuffer, uint dwInBufferSize, ref byte[] lpOutBuffer, uint dwOutBufferSize, ref uint lpBytesReturned);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardReconnect(IntPtr hCard, SCardShareMode dwShareMode,
          SCardProtocol dwPrefProtocol, SCardDisposition dwInitialization, ref SCardProtocol ActiveProtocol);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardDisconnect(IntPtr hCard, SCardDisposition Disposition);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardListReaderGroups(IntPtr hContext, ref string mszGroups, ref uint nStringSize);

        [DllImport("WinScard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Auto)]
        public static extern PCSCResult SCardListReaders(
          IntPtr hContext,
          byte[] mszGroups,
          byte[] mszReaders,
          ref UInt32 pcchReaders
          );

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardFreeMemory(IntPtr hContext, IntPtr pvMem);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardGetAttrib(IntPtr hCard, uint dwAttrId, byte[] pbRecvAttr, ref IntPtr nRecLen);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardTransmit(IntPtr hCard,
            IntPtr pioSendPci, byte[] pbSendBuffer, int cbSendLength,
            IntPtr pioRecvPci, byte[] pbRecvBuffer, ref int pcbRecvLength);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardBeginTransaction(IntPtr hCard);

        [DllImport("WinScard.dll")]
        public static extern PCSCResult SCardEndTransaction(IntPtr hCard, SCardDisposition dwDisposition);

        public static string SCardErrorMessage(int error)
        {
            return new Win32Exception(error).Message;
        }



        /// <summary>
        /// The maximum length of the atr buffer used in various calls
        /// </summary>
        public const int SCARD_ATR_LENGTH = 32;

        #endregion
    }

    public enum SCardScope : uint
    {
        User = 0x00,
        Terminal = 0x01,
        System = 0x02
    }

    [Flags]
    public enum SCardProtocol
    {
        Undefined = 0x00,
        T0 = 0x01,
        T1 = 0x02,
        Raw = 0x04,
        T15 = 0x08,
        Any = T0 | T1
    }

    public enum SCardShareMode : uint
    {
        Undefined = 0x00,
        Exclusive = 0x01,
        Shared = 0x02,
        Direct = 0x03
    }

    public enum SCardDisposition : uint
    {
        LeaveCard = 0x00,
        ResetCard = 0x01,
        UnpowerCard = 0x02,
        EjectCard = 0x03
    }

    [Flags]
    public enum SCardState : uint
    {
        Unaware = 0x0000,
        Ignore = 0x0001,
        Changed = 0x0002,
        Unknown = 0x0004,
        Unavailable = 0x0008,
        Empty = 0x0010,
        Present = 0x0020,
        AtrMatch = 0x0040,
        Exclusive = 0x0080,
        InUse = 0x0100,
        Mute = 0x0200,
        Unpowered = 0x0400
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    internal struct SCARD_READERSTATE
    {
        [MarshalAs(UnmanagedType.LPTStr)]
        public string szReader;
        public IntPtr pvUserData;
        public SCardState dwCurrentState;
        public SCardState dwEventState;
        public int cbAtr;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public byte[] rgbAtr;
    }

    /// <summary>
    /// Some of the Windows PCSC calls will use this structure.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal class SCARD_IO_REQUEST
    {
        public uint Protocol;
        public int PciLength;

        public SCARD_IO_REQUEST()
        {
            Protocol = 0;
        }

    }

}
#endregion