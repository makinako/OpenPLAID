
//
// Uncomment this symbol to enable selection of the PLAID and PACSAM applications for every PLAID personalisation operation.
// It is used for debugging with JCIDE debugger
//
//#define PLAIDEXPLICITSELECT

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
using System.Linq;
using CardFramework.Protocols.Iso7816;
using CardFramework.Applications.Iso7816;
using System.Diagnostics;
using System.Collections.Generic;
#endregion

#region "Class definitions"
namespace CardFramework.Applications.Plaid
{
    public class PlaidKey
    {
        public short KeysetId;
        public RSAKey IAKey;
        public byte[] FAKey;
    }

    public class PlaidApplication : Iso7816Application
    {
        #region "Members - Public"

        public override bool Discover(Card card)
        {
            // Create a backup of the reference to our old card
            Card oldCard = this.Card;

            // Temporarily set the card
            this.Card = card;

            try
            {
                SelectApplication();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                this.Card = oldCard;
            }
        }

        public void SelectApplication()
        {
            byte[] response = SelectFile(AID, SelectMode.DfName);
            return;
        }

        /// <summary>
        /// This method performs the full PLAID authentication sequence, given a valid, selected PLAID SAM
        /// and a collection of keysets
        /// </summary>
        /// <param name="sam">The instance of a PLAID SAM</param>
        /// <param name="keysets">The collection of keyset identifiers to request</param>
        /// <param name="opMode">The requested opMode</param>
        /// <returns>The ACSRecord associated with the requested OpMode</returns>
        public byte[] Authenticate(IPlaidSAM sam, KeysetList keysets, short samId, short opMode)
        {
            // Initial Authenticate
#if PLAIDEXPLICITSELECT
            SelectApplication();
#endif
            byte[] estr1 = InitialAuthenticate(keysets);
#if PLAIDEXPLICITSELECT
            sam.SelectApplication(); // REMOVE
#endif
            byte[] estr2 = sam.InitialAuthenticate(samId, estr1, opMode);

            // Final Authenticate
#if PLAIDEXPLICITSELECT
            SelectApplication();
#endif
            byte[] estr3 = FinalAuthenticate(estr2);
#if PLAIDEXPLICITSELECT
            sam.SelectApplication(); // REMOVE
#endif

            return sam.FinalAuthenticate(estr3);
        }

        /// <summary>
        /// This method performs the full PLAID authentication sequence, given a valid, selected PLAID SAM
        /// and a single keyset
        /// </summary>
        /// <param name="sam">The instance of a PLAID SAM</param>
        /// <param name="keyset">The single keyset identifier to request</param>
        /// <param name="opMode">The requested opMode</param>
        /// <returns>The ACSRecord associated with the requested OpMode</returns>
        public byte[] Authenticate(IPlaidSAM sam, short keysetId, short samId, short opMode)
        {
            return Authenticate(sam, new KeysetList(keysetId), samId, opMode);
        }

        public byte[] InitialAuthenticate(KeysetList keysets)
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_PLAID_INITIAL_AUTH;
            command.P1 = 0x00;
            command.P2 = 0x00;
            command.Data = keysets.Encode();

            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("InitialAuthenticate");
            }

            return response.Data;
        }

        public byte[] FinalAuthenticate(byte[] estr2)
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_PLAID_FINAL_AUTH;
            command.P1 = 0x00;
            command.P2 = 0x00;
            command.Data = estr2;

            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("FinalAuthenticate");
            }

            return response.Data;
        }

        public void ResetAuthentication()
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            // Construct the APDU
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_RESET_AUTH;
            command.P1 = 0x00;
            command.P2 = 0x00;
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("SetData");
            }

            return;
        }


        public void SetData(byte[] cryptogram)
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            // Construct the APDU
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_SET_DATA;
            command.P1 = 0x00;
            command.P2 = 0x00;
            command.Data = cryptogram;
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("SetData");
            }

            return;
        }

        public byte[] GetData(byte element)
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            // Construct the APDU
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_GET_DATA;
            command.P1 = element;
            command.P2 = 0x00;
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GetData");
            }

            return response.Data;
        }

        public PlaidStatus GetStatus()
        {
            Iso7816Protocol protocol = Card.GetProtocol<Iso7816Protocol>();

            // Construct the APDU
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = INS_GET_STATUS;
            command.P1 = 0x00;
            command.P2 = 0x00;
            RApdu response = protocol.Transceive(command);

            // Validate the response,
            if (response.IsError)
            {
                throw response.ThrowBySW("GetStatus");
            }

            PlaidStatus status = new PlaidStatus(response.Data);
            return status;
        }

        public bool Verify(IPlaidSAM sam, PlaidTemplate template, Dictionary<string, byte[]> parameters = null)
        {
            SelectApplication();

            bool result = true;

            // Validate the PLAID applet status is STATE_SELECTABLE
            var status = GetStatus();

            // Validate our personalisation status, depending on whether the template automatically blocks the applet
            if (template.Blocked)
            {
                if (status.AppletState == PlaidAppletState.Blocked)
                {
                    RaiseOnMessage(@"PASS: Applet state is set to Blocked");
                }
                else
                {
                    RaiseOnMessage(@"FAIL: Applet state is not set to Blocked");
                    result = false;
                }
            }
            else
            {
                if (status.AppletState == PlaidAppletState.Personalised)
                {
                    RaiseOnMessage(@"PASS: Applet state is set to Personalised");
                }
                else
                {
                    RaiseOnMessage(@"FAIL: Applet state is not set to Personalised");
                    result = false;
                }
            }


            // Load all Keysets in descending order so that KEYSET_ADMIN is last
            foreach (var keyset in template.Keysets.OrderByDescending(x => x.Id))
            {
                if (template.Blocked && keyset.Id != KEYSET_ADMIN)
                {
                    RaiseOnMessage(@"SKIP: Authenticate keyset '" + keyset.IdBytes.ToHexString() + "' (application blocked)");
                    continue;
                }

                try
                {
                    Authenticate(sam, keyset.Id, keyset.SamId, 0);
                    RaiseOnMessage(@"PASS: Authenticate keyset '" + keyset.IdBytes.ToHexString() + "'");
                }
                catch (Exception)
                {
                    RaiseOnMessage(@"FAIL: Authenticate keyset '" + keyset.IdBytes.ToHexString() + "'");
                    result = false;
                }
                
            }

            // Verify all ACSRecords
            foreach (var record in template.ACSRecords)
            {
                // Determine the actual data
                byte[] expectedData;
                if (record.IsTemplate())
                {
                    expectedData = parameters[record.Data];
                }
                else
                {
                    expectedData = record.DataToArray();
                }

                // Retrieve the ACSRecord with the KEYSET_ADMIN keyset so we know we can always have permission to read it
                var keyset = template.Keysets.First(k => k.Id == KEYSET_ADMIN);
                byte[] actualData = Authenticate(sam, keyset.Id, keyset.SamId, record.OpModeId);

                // Compare the byte arrays
                if (expectedData.SequenceEqual(actualData))
                {
                    RaiseOnMessage(@"PASS: Retrieve ACSRecord '" + record.OpModeIdBytes.ToHexString() + "' (" + actualData.ToHexString() + ")");
                }
                else
                {
                    RaiseOnMessage(@"FAIL: Retrieve ACSRecord '" + record.OpModeIdBytes.ToHexString() + "' (expected '" + expectedData.ToHexString() + "' but got '" + actualData.ToHexString() + "')");
                    result = false;
                }
            }

            // Done!
            return result;
        }

        public void Personalise(IPlaidSAM sam, PlaidTemplate template, Dictionary<string, byte[]> parameters = null)
        {
            SelectApplication();

            // Validate the PLAID applet status is STATE_SELECTABLE
            var status = GetStatus();
            if (status.AppletState != PlaidAppletState.Selectable)
            {
                RaiseOnMessage(@"PLAID: Already personalised (performing factory reset)");
                // During debugging, perform a factory reset
                if (status.AppletState == PlaidAppletState.Terminated)
                {
                    throw new ApplicationException(@"Invalid applet state for factory reset");
                }

                // Authenticate using the administrative key
                var adminKeyset = template.Keysets.First(x => x.Id == PlaidApplication.KEYSET_ADMIN);
                Authenticate(sam, adminKeyset.Id, adminKeyset.SamId, 0);

                // Perform a FACTORY_RESET command
                {
                    var request = new FactoryResetRequest();

#if PLAIDEXPLICITSELECT
                    sam.SelectApplication();
#endif
                    byte[] cryptogram = sam.SetData(request.Encode());

#if PLAIDEXPLICITSELECT
                    SelectApplication();
#endif
                    SetData(cryptogram);
                }
            }

            // Retrieve and load the FA KEY cryptogram
            RaiseOnMessage(@"PLAID: Retrieving transport cryptogram");
            byte[] faKey = GetData(0x00);
#if PLAIDEXPLICITSELECT
            sam.SelectApplication();
#endif
            sam.LoadFAKey(template.TransportKey.SamId, faKey);

            // Authenticate using the TransportKey key
            // NOTE: We don't care which OpMode we request since this is an administrative authentication
            RaiseOnMessage(@"PLAID: Authenticating with transport admin keyset");
            byte[] acsRecord = Authenticate(sam, template.TransportKey.Id, template.TransportKey.SamId, 0);

            // Load all ACSRecords
            foreach (var record in template.ACSRecords)
            {
                // Create the request object
                var request = new AcsrCreateRequest();
                request.Id = record.OpModeId;

                if (record.IsTemplate())
                {
                    request.Data = parameters[record.Data];
                } else
                {
                    request.Data = record.DataToArray();
                }

                RaiseOnMessage($"PLAID: Writing ACSRecord {request.Id} ({request.Data.ToHexString()})");

                // Generate the cryptogram
#if PLAIDEXPLICITSELECT
                sam.SelectApplication();
#endif
                byte[] cryptogram = sam.SetData(request.Encode());

                // Transmit to the ICC
#if PLAIDEXPLICITSELECT
                SelectApplication();
#endif
                SetData(cryptogram);
            }

            // Load all Keysets in descending order so that KEYSET_ADMIN is last
            foreach (var keyset in template.Keysets.OrderByDescending(x => x.Id))
            {
                // Create the request object
                var request = new KeyCreateRequest();

                request.Id = keyset.Id;
                request.SamId = keyset.SamId;

                foreach (var rule in keyset.AccessRules) request.Rules.Add(rule);

                // Generate the cryptogram
#if PLAIDEXPLICITSELECT
                sam.SelectApplication();
#endif
                RaiseOnMessage($"PLAID: Loading keyset {keyset.Id:X4}");
                byte[] cryptogram = sam.SetData(request.Encode());

                // Transmit to the ICC
#if PLAIDEXPLICITSELECT
                SelectApplication();
#endif
                SetData(cryptogram);

            }

            // Re-authenticate with the Administrative key
            // NOTE: We don't care which OpMode we request since this is an administrative authentication
            RaiseOnMessage(@"PLAID: Authenticating with admin keyset");
            Authenticate(sam, template.AdminKey.Id, template.AdminKey.SamId, 0);

            // Activate the instance
            {
                RaiseOnMessage(@"PLAID: Updating applet state to PERSONALISED");
                var request = new ActivateRequest();

#if PLAIDEXPLICITSELECT
                sam.SelectApplication();
#endif
                byte[] cryptogram = sam.SetData(request.Encode());

#if PLAIDEXPLICITSELECT
                SelectApplication();
#endif
                SetData(cryptogram);
            }

            // If required, Block the instance
            if (template.Blocked)
            {
                RaiseOnMessage(@"PLAID: Updating applet state to BLOCKED");
                var request = new BlockRequest();

#if PLAIDEXPLICITSELECT
                sam.SelectApplication();
#endif
                byte[] cryptogram = sam.SetData(request.Encode());

#if PLAIDEXPLICITSELECT
                SelectApplication();
#endif
                SetData(cryptogram);
            }

            // Done!
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        /// <summary>
        /// The PLAID Application Identifier (AID)
        /// </summary>
        public static readonly byte[] AID = { 0xE0, 0x28, 0x81, 0xC4, 0x61, 0x01 };

        /// <summary>
        /// Static CLA value for all commands
        /// </summary>
        public const byte CLA = 0x00; // Static CLA value for all commands

        //
        // Applet Commands - Administrative (Non-ISO)
        //
        public const byte INS_GET_DATA = 0x81;
        public const byte INS_SET_DATA = 0x82;
        public const byte INS_GET_STATUS = 0x83;
        public const byte INS_RESET_AUTH = 0x84;

        //
        // Applet Commands - PLAID (ISO)
        //
        public const byte INS_PLAID_INITIAL_AUTH = 0x87;
        public const byte INS_PLAID_FINAL_AUTH = 0x86;

        //
        // PLAID authentication states
        // 
        public const byte AUTH_STATE_NONE = 0;
        public const byte AUTH_STATE_IAKEY = 1;
        public const byte AUTH_STATE_OK = 2;
        public const byte AUTH_STATE_SHILL = 3;

        public const short LENGTH_BLOCK_AES = 16;
        public const short LENGTH_KEY_AES = 16;
        public const short LENGTH_BLOCK_RSA = 256;
        public const short LENGTH_KEY_RSA = 256;
        public const short LENGTH_PUBLIC_EXPONENT = 3;

        //
        // PLAID protocol constants (ISO)
        // 
        public const short LENGTH_PAYLOAD = 0; // Optional Payloads feature not implemented
        public const short LENGTH_KEYSET_ID = 2;
        public const short LENGTH_OPMODE_ID = 2;
        public const short LENGTH_ACSRECORD =16;
        public const short LENGTH_KEYSHASH = LENGTH_KEY_AES;
        public const short LENGTH_DIVDATA = LENGTH_BLOCK_AES;
        public const short LENGTH_RND1 = LENGTH_BLOCK_AES;
        public const short LENGTH_RND2 = LENGTH_BLOCK_AES;
        public const short LENGTH_STR1 = (LENGTH_KEYSET_ID + LENGTH_DIVDATA + LENGTH_RND1 + LENGTH_RND1);
        public const short LENGTH_STR2 = (LENGTH_OPMODE_ID + LENGTH_RND2 + LENGTH_PAYLOAD + LENGTH_KEYSHASH);
        public const short LENGTH_STR3 = (LENGTH_ACSRECORD + LENGTH_PAYLOAD + LENGTH_DIVDATA);

        //
        // Applet Constant
        //
        public const short KEYSET_ADMIN = 0x0000;

        #endregion
    }
}
#endregion