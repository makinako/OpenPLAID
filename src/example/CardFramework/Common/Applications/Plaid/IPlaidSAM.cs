using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CardFramework.Applications.Plaid
{
    public interface IPlaidSAM
    {
        /// <summary>
        /// Selects the PLAID SAM applet instance by its AID
        /// </summary>
        void SelectApplication();

        /// <summary>
        /// Performs the IFD-side calculation of the PLAID Initial Authenticate command
        /// </summary>
        /// <param name="keyId">The SAM Id to the requested keyset</param>
        /// <param name="estr1">The encrypted STR1 response from the ICC</param>
        /// <param name="opMode">The requested opMode</param>
        /// <returns>The encrypted STR2 cryptogram to pass to the ICC for final authentication</returns>
        /// <remarks>Normally, all requested keys </remarks>
        byte[] InitialAuthenticate(short keyId, byte[] estr1, short opMode);

        /// <summary>
        /// Performs the IFD-side calculation of the PLAID Final Authentication command
        /// </summary>
        /// <param name="estr3">The encrypted STR3 response from the ICC</param>
        /// <returns>The decrypted ACSRecord that was previously requested</returns>
        byte[] FinalAuthenticate(byte[] estr3);

        /// <summary>
        /// Creates a cryptogram from an ASN1 command using the currently authenticated session key.
        /// </summary>
        /// <param name="command">The ASN1-formatted command to be prepared.</param>
        /// <returns>The cryptogram to be transmitted to the ICC</returns>
        /// <remarks>The currently authenticated key must have the PLAID_KEK attribute set</remarks>
        byte[] SetData(byte[] command);

        /// <summary>
        /// Loads the encrypted FA key into the SAM volatile memory, to be used for the next authentication
        /// </summary>
        /// <param name="keyId">The SAM Id to the decrypting keyset</param>
        /// <param name="cryptogram">The cryptogram received from the ICC 'GET DATA' command</param>
        void LoadFAKey(short keyId, byte[] cryptogram);
    }
}
