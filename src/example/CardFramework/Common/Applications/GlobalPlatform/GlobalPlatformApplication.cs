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
using CardFramework.Protocols.Iso7816;
using CardFramework.Applications.Iso7816;
#endregion

#region "Class definitions"
namespace CardFramework.Applications.GlobalPlatform
{
    /// <summary> 
    /// Card life-cycle State enumeration values as per GlobalPlatform 2.2 - 5.1.1
    /// </summary>
    public enum CardLifeCycle
    {
        /// <summary>
        /// The state OP_READY indicates that the runtime environment shall be available and the Issuer Security Domain, acting as the selected Application, shall be ready to receive, execute and respond to APDU commands.
        /// </summary>
        OpReady = 0x01,

        /// <summary>
        /// This state may be used to indicate that some initial data has been populated (e.g. Issuer Security Domain keys and/or data) but that the card is not yet ready to be issued to the Cardholder.
        /// </summary>
        Initialized = 0x07,

        /// <summary>
        /// The SECURED state should be used to indicate to off-card entities that the Issuer Security Domain contains all necessary keys and security elements for full functionality.
        /// </summary>
        Secured = 0x0F,

        /// <summary>
        /// Setting the card to this state means that the card shall only allow selection of the application with the Final Application privilege.
        /// </summary>
        CardLocked = 0xEF,

        /// <summary>
        /// The state TERMINATED signals the end of the card Life Cycle and the card. The state transition from any other state to TERMINATED is irreversible.
        /// </summary>
        Terminated = 0xFF
    }

    /// <summary>
    /// Executable life-cycle state enumeration values as per GlobalPlatform 2.2 - 5.2.1
    /// </summary>
    public enum ExecutableLifeCycle
    {
        /// <summary>
        /// The OPEN shall consider all Executable Load Files present in the card in Immutable Persistent Memory or Mutable Persistent Memory to be in the state LOADED. 
        /// </summary>
        Loaded = 0x01
    }

    /// <summary>
    /// Application life-cycle state enumeration values as per GlobalPlatform 2.2 - 5.3.1
    /// </summary>
    /// <remarks>
    /// Bits b4-b7 are application specific, so they must be ignored when testing for the application life cycle value.
    /// </remarks>
    public enum ApplicationLifeCycle
    {
        /// <summary>
        /// The state INSTALLED means that the Application executable code has been properly linked and that any necessary memory allocation has taken place. 
        /// </summary>
        Installed = 0x03,

        /// <summary>
        /// The state SELECTABLE means that the Application is able to receive commands from off-card entities. 
        /// </summary>
        Selectable = 0x07,

        /// <summary>
        /// The OPEN, the Application itself, the Application's associated Security Domain, an Application with the Global Lock privilege or a Security Domain with the Global Lock privilege uses the state LOCKED as a security management control to prevent the selection, and therefore the execution, of the Application.
        /// </summary>
        Locked = 0x83
    }

    /// <summary>
    /// Security Domain life-cycle state enumeration values as per GlobalPlatform 2.2 - 5.3.2
    /// </summary>
    public enum SecurityDomainLifeCycle
    {
        /// <summary>
        /// The state INSTALLED means that the Security Domain becomes an entry in the GlobalPlatform Registry and this entry is accessible to off-card entities authenticated by the associated Security Domain.
        /// </summary>
        Installed,

        /// <summary>
        /// The state SELECTABLE means that the Security Domain is able to receive commands (specifically personalization commands) from off-card entities.
        /// </summary>
        Selectable,

        /// <summary>
        /// he definition of what is required for a Security Domain to transition to the state PERSONALIZED is Security Domain dependent but is intended to indicate that the Security Domain has all the necessary personalization data and keys for full runtime functionality (i.e. usable in its intended environment). 
        /// </summary>
        Personalized,

        /// <summary>
        /// The OPEN, the Security Domain itself, the Security Domain's associated Security Domain (if any), an Application with the Global Lock privilege or a Security Domain with the Global Lock privilege uses the state LOCKED as a security management control to prevent the selection of the Security Domain.
        /// </summary>
        Locked
    }

    public class GlobalPlatformApplication : Iso7816Application
    {
        #region "Members - Public"

        public override bool Discover(Card card)
        {
            return true;
        }


        public void Delete()
        {
        }

        public void GetStatus()
        {

        }

        public void Install()
        {

        }

        public void Load()
        {

        }

        public void ManageChannel()
        {

        }

        public void PutKey()
        {

        }

        public void SetStatus()
        {

        }

        public void StoreData()
        {

        }

        public Cplc ReadCplc()
        {
            byte[] buffer = GetData(FileIdCplc);
            return Cplc.Parse(buffer);
        }

        public void SelectApplication()
        {
            byte[] response = null;

            try
            {
                // First, attempt to select the GlobalPlatform AID (newer, used by Oberthur)
                response = SelectFile(AidGlobalPlatform, SelectMode.DfName);
            }
            catch
            {
                try
                {
                    // Next, fall back to the original Visa OpenPlatform aid
                    response = SelectFile(AidOpenPlatform, SelectMode.DfName);
                }
                catch
                {
                    throw;
                }
            }
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"
        public static readonly byte[] FileIdCplc = { 0x9F, 0x7F };
        public static readonly byte[] AidOpenPlatform = { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
        public static readonly byte[] AidGlobalPlatform = { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 };

        #endregion
    }
}
#endregion
