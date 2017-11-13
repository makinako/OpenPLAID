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
using System.Linq;
using CardFramework.Protocols.Iso7816;
using CardFramework.Applications.Iso7816;
using System.IO;
using CardFramework.Helpers;
using CardFramework.Applications.DESFire;
using System.Text;
using CardFramework.Applications.Plaid;
using System.Collections;
#endregion

// CLEANUP
// - Fix up the RAPDU error handling in every method here

#region "Class definitions"
namespace CardFramework.Applications.PACSAM
{
    /// <summary>
    /// Implementation of the DESFire EV-1 (MF3ICDx1) application
    /// </summary>
    /// <remarks>
    /// This is classed as an Application, rather than a Protocol because we are using the ISO-wrapped mode
    /// of communications, not native proprietary.
    /// </remarks>
    public class PACSAMApplication : Iso7816Application, IDESFireSAM, IPlaidSAM, IEnumerable<PACSAMKey>
    {
        #region "Members - Public"

        public byte[] AID = new byte[] { 0xE0, 0x28, 0x81, 0xC4, 0x61, 0x4B, 0x4F };

        /// <summary>
        /// Holds the state from the most recent DESFire authentication
        /// </summary>
        public DESFireAuthStatus DESFireStatus { get; private set; }

        /// <summary>
        /// Holds the state from the most recent PLAID authentication
        /// </summary>
        public PlaidAuthStatus PlaidStatus { get; private set; }

        public override bool Discover(Card card)
        {
            Card = card;

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
                Card = null;
            }
        }

        #endregion

        #region "Members - Private / Protected"

        public const int ESNLength = 4;
        public const int PinLength = 6;
        public const int MaximumPinRetries = 10;

        private List<PACSAMKey> myKeys = new List<PACSAMKey>();
        public PACSAMKey this[int index]
        {
            get
            {
                return myKeys[index];
            }
        }

        public void SelectApplication()
        {
            byte[] response = SelectFile(AID, SelectMode.DfName);
        }

        public void SetData(SetDataElement element, byte[] data)
        {
            // Transceive
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.SetData, p1: (byte)element, data: data);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "SetData");
            }

            // If we get a valid response then everything went OK and the PACSAM instance now has a session key established.
        }

        public PACSAMStatus GetStatus()
        {
            // Transceive
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.GetStatus);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "GetStatus");
            }

            PACSAMStatus status = new PACSAMStatus();
            BinaryParser parser = new BinaryParser(response.Data, ByteEndianess.BigEndian);

            // Applet state
            status.AppletState = (PACSAMAppletState)parser.ReadUInt8();

            // ESN
            status.ESN = parser.ReadUInt32();

            // Encoding Profile
            status.Profile = parser.ReadUInt16();

            // System Diversifier
            status.SystemDiversifier = parser.ReadBytes(PACSAMStatus.SystemDivLength);

            // DESFire Authentication Status
            status.DESFireStatus = (DESFireAuthStatus)parser.ReadUInt8();

            // PLAID Authentication Status
            status.PlaidStatus = (PlaidAuthStatus)parser.ReadUInt8();

            // PIN Authentication Status
            status.PINStatus = Convert.ToBoolean(parser.ReadUInt8());

            // Done
            return status;
        }

        private void ResetAuthentication()
        {
            try
            {
                // Transceive
                RApdu response = Transcieve(CLA, (byte)PACSAMCommand.ResetAuth);

                // Check for an error response
                if (response.IsError)
                {
                    throw new Iso7816Exception(response.SW12, "ResetAuthentication");
                }
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                // Reset our internal states anyway
                DESFireStatus = DESFireAuthStatus.AUTH_STATE_NONE;
                PlaidStatus = PlaidAuthStatus.AUTH_STATE_NONE;
            }
        }

        public void VerifyPIN(string pin)
        {
            const int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
            const int SW_SW_PIN_TRIES_REMAINING = 0x63C0;

            // Validate the PIN
            if (String.IsNullOrEmpty(pin)) throw new ArgumentException("The PIN must not be empty");

            // Trim the PIN
            pin = pin.Trim();

            // Validate the PIN (Numeric check)
            if (!pin.All(char.IsDigit)) throw new ArgumentException("The PIN must be numeric");

            // Validate the PIN length
            if (pin.Length != PinLength) throw new ArgumentException($"The PIN must be {PinLength} digits in length exactly");

            // TransceivePinLength
            byte[] pinData = Encoding.ASCII.GetBytes(pin);
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.VerifyPin, data: pinData);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                // Check for invalid PIN
                if ( (response.SW12 & 0xFFF0) == SW_SW_PIN_TRIES_REMAINING)
                {
                    int triesRemaining = (response.SW2 & 0x0F);
                    // Invalid PIN
                    throw new Iso7816Exception(response.SW12, string.Format("The PIN is incorrect ({0} tries remaining)", triesRemaining));
                }
                // Check for TERMINATED
                else if (response.SW12 == SW_SECURITY_STATUS_NOT_SATISFIED)
                {
                    throw new Iso7816Exception(response.SW12, "The PACSAM has been terminated (too many incorrect PIN attempts)");
                }
                else
                {
                    throw new Iso7816Exception(response.SW12, "VerifyPIN");
                }
            }
        }

        public void Activate()
        {
            // Transceive
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.Activate);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "Activate");
            }
        }

        public void Terminate()
        {
            // Transceive
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.Terminate);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "Terminate");
            }
        }

        public void Personalise(uint esn, string pin, PACSAMKeyFile keys)
        {

            /*
             * Input validation
             */

            // Validate the ESN
            if (esn == 0) throw new ArgumentException("The ESN must not be zero");

            // Validate the PIN
            if (String.IsNullOrEmpty(pin)) throw new ArgumentException("The PIN must not be empty");

            // Trim the PIN
            pin = pin.Trim();

            // Validate the PIN (Numeric check)
            if (!pin.All(Char.IsDigit)) throw new ArgumentException("The PIN must be numeric");

            // Validate the PIN length
            if (pin.Length != PinLength) throw new ArgumentException($"The PIN must be {PinLength} digits in length exactly");

            // Validate the key record file
            if (keys == null) throw new ArgumentException("The key container is empty");

            // Validate the key integrity
            foreach (PACSAMKeyRecord r in keys.Records)
            {
                if (!r.VerifyHash()) throw new InvalidDataException(string.Format("The key record '{0}' failed it's hash check"));
            }

            /*
             * Personalisation steps
             * 
             * NOTE:
             * We don't check whether this PACSAM instance is actually in the correct state to personalise.
             * We just try it and if it fails it fails.
             */

            // Select the PACSAM Application
            try
            {
                SelectApplication();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to SelectApplication failed", ex);
            }

            // Validate the PACSAM is in the SELECTABLE state
            try
            {
                var status = GetStatus();
                if (status.AppletState != PACSAMAppletState.Selectable)
                    throw new InvalidOperationException("This PACSAM instance is not in the SELECTABLE state");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to GetStatus failed", ex);
            }



            // Set the ESN
            try
            {
                SetData(SetDataElement.ESN, BinaryParser.ConvertUInt32(esn, ByteEndianess.BigEndian));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to SET DATA failed (esn)", ex);
            }

            // Set the PIN
            try
            {
                byte[] pinData = ASCIIEncoding.ASCII.GetBytes(pin);
                SetData(SetDataElement.PIN, pinData);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to SET DATA failed (PIN)", ex);
            }

            // Set the Profile Identifier
            try
            {
                SetData(SetDataElement.Profile, keys.IdBytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to SET DATA failed (Profile Identifier)", ex);
            }

            // Set the System Diversifier
            try
            {
                SetData(SetDataElement.SystemDiversifier, keys.SystemDiversifier);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("The call to SET DATA failed (System Diversifier)", ex);
            }

            // Write the keys
            foreach (PACSAMKeyRecord r in keys.Records)
            {
                // TDEA2KEY
                if (typeof(PACSAMTDEA2KeyRecord).IsAssignableFrom(r.GetType()))
                {
                    LoadKey(PACSAMKeyType.DES, 0, r.PackRecord());
                }

                // AES128
                else if (typeof(PACSAMAES128KeyRecord).IsAssignableFrom(r.GetType()))
                {
                    LoadKey(PACSAMKeyType.AES, 0, r.PackRecord());
                }

                // PLAID
                else if (typeof(PACSAMPlaidKeyRecord).IsAssignableFrom(r.GetType()))
                {
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyPElement, r.PackRecord("IAKEY_P"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyQElement, r.PackRecord("IAKEY_Q"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyPQElement, r.PackRecord("IAKEY_PQ"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyDPElement, r.PackRecord("IAKEY_DP"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyDQElement, r.PackRecord("IAKEY_DQ"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyModulusElement, r.PackRecord("IAKEY_MODULUS"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.IAKeyExponentElement, r.PackRecord("IAKEY_EXPONENT"));
                    LoadKey(PACSAMKeyType.PLAID, PACSAMPlaidKeyRecord.FAKeyElement, r.PackRecord("FAKEY"));
                }
            }

            // Activate this PACSAM instance
            Activate();
        }

        public void LoadKey(PACSAMKeyType keyType, byte element, byte[] record)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.LoadKey;
            command.P1 = (byte)keyType;
            command.P2 = element;
            command.Data = record;

            // NOTE: For some reason I get poor handling of Extended APDU's when supplying the LE byte. This may only be relevant to the Javacos virtual reader
            // but for now we just omit it.
            if (record.Length <= 255) command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "LoadKey");
            }
        }

        public PACSAMKey ReadNextKey(short index)
        {
            byte[] indexBytes = BinaryParser.ConvertInt16(index, ByteEndianess.BigEndian);

            // Transceive
            RApdu response = Transcieve(CLA, (byte)PACSAMCommand.ReadNextKey, indexBytes[0], indexBytes[1]);
            
            // Parse and test
            if (response.IsError)
            {
                // Check specifically for the SW_RECORD_NOT_FOUND status
                if (response.SW12 == 0x6A83) return null;

                // A legit error
                throw new Iso7816Exception(response.SW12, "ReadNextKey");
            }

            return new PACSAMKey(response.Data);
        }

        public void ClearKeys()
        {
            myKeys.Clear();
        }

        public List<PACSAMKey> ReadAllKeys()
        {
            short index = 0;

            ClearKeys();

            while (true)
            {
                // Read the next key
                PACSAMKey key = ReadNextKey(index);

                // If null, there are no more keys
                if (key == null) return myKeys;

                // Add to our list
                myKeys.Add(key);

                // Progress our index to the next one
                index = (short)(key.Index + 1);
            }

        }

        /* 
         * DESFireEV1 Commands
         */


        public byte[] EV1Authenticate0(short keyIndex, byte[] ekRndB)
        {
            // This command will reset our authentication status
            //ResetAuthentication();

            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1Auth0;
            command.P1 = (byte)((keyIndex >> 8) & 0xFF); // Key index MSB
            command.P2 = (byte)(keyIndex & 0xFF);        // Key index LSB

            MemoryStream data = new MemoryStream();

            // ekRndB (from PICC)
            data.Write(ekRndB, 0, ekRndB.Length);

            command.Data = data.ToArray();
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1Authenticate0");
            }

            return response.Data;
        }

        public void EV1Authenticate1(byte[] ekRndA)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1Auth1;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = ekRndA;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1Authenticate1");
            }

            // If we get a valid response then everything went OK and the PACSAM instance now has a session key established.
            // Confirm this by interrogating the PACSAM
            var status = GetStatus();
            if ((status.DESFireStatus != DESFireAuthStatus.AUTH_STATE_OK_DES) &&
                (status.DESFireStatus != DESFireAuthStatus.AUTH_STATE_OK_ISO) &&
                (status.DESFireStatus != DESFireAuthStatus.AUTH_STATE_OK_AES))
            {
                throw new InvalidOperationException(@"PACSAM authentication state not changed. Authentication failed.");
            }
        }

        public byte[] EV1ChangeKey(byte keyNo, short newIndex, short? oldIndex = null)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1ChangeKey;
            command.P1 = keyNo;
            command.P2 = 0;

            MemoryStream data = new MemoryStream();

            data.WriteByte((byte)((newIndex >> 8) & 0xFF)); // Key index MSB
            data.WriteByte((byte)(newIndex & 0xFF));        // Key index LSB

            if (oldIndex != null)
            {
                data.WriteByte((byte)((oldIndex >> 8) & 0xFF)); // Key index MSB
                data.WriteByte((byte)(oldIndex & 0xFF));        // Key index LSB
            }

            command.Data = data.ToArray();
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1ChangeKey");
            }

            // Return the cryptogram
            return response.Data;
        }

        public byte[] EV1GenerateMAC(byte[] data)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1GenerateMac;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = data;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1GenerateMAC");
            }

            // Done
            return response.Data;
        }

        public bool EV1VerifyMAC(byte[] data)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1verifyMac;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = data;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                //throw new Iso7816Exception(response.SW12, "EV1VerifyMAC");
                return false;
            }

            // Done
            return true;
        }

        public byte[] EV1EncipherData(byte[] data)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1Encipher;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = data;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1EncipherData");
            }

            // Done
            return response.Data;
        }

        public byte[] EV1DecipherData(byte[] data, byte expectedLength = 0)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1Decipher;
            command.P1 = expectedLength; // TODO: Implement the usage of this parameter
            command.P2 = 0;
            command.Data = data;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1DecipherData");
            }

            // Done
            return response.Data;
        }

        public void EV1UpdateIV(byte[] data)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1UpdateIV;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = data;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1UpdateIV");
            }
        }

        public void EV1SetDivData(byte[] divData)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.EV1SetDivData;
            command.P1 = 0;
            command.P2 = 0;
            command.Data = divData;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "EV1SetDivData");
            }

            // If we get a valid response then everything went OK and the PACSAM instance now has a session key established.
        }


        /*
         * PLAID Commands
         */

        public byte[] PlaidInitialAuthenticate(short keyIndex, byte[] estr1, short opMode)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.PlaidInitialAuth;
            command.P1 = (byte)((keyIndex >> 8) & 0xFF); // Key index MSB
            command.P2 = (byte)(keyIndex & 0xFF);        // Key index LSB

            // Generate the full APDU data
            MemoryStream data = new MemoryStream();
            data.WriteByte((byte)((opMode >> 8) & 0xFF)); // Key index MSB
            data.WriteByte((byte)(opMode & 0xFF));        // Key index LSB
            data.Write(estr1, 0, estr1.Length);
            command.Data = data.ToArray();
            //command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test DESFire status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "PlaidInitialAuthenticate");
            }

            return response.Data;
        }

        public byte[] PlaidFinalAuthenticate(byte[] estr3)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.PlaidFinalAuth;
            command.P1 = 0x00;
            command.P2 = 0x00;
            command.Data = estr3;
            command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "PlaidFinalAuthenticate");
            }

            return response.Data;
        }

        public byte[] PlaidSetData(byte[] commandObject)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.PlaidSetData;
            command.P1 = 0x00;
            command.P2 = 0x00;
            command.Data = commandObject;
            //command.LE = 0x00;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "PlaidSetData");
            }

            return response.Data;
        }

        public void PlaidLoadFAKey(short keyIndex, byte[] cryptogram)
        {
            // Setup the command
            CApdu command = new CApdu();
            command.Cla = CLA;
            command.Ins = (byte)PACSAMCommand.PlaidLoadFAKey;
            command.P1 = (byte)((keyIndex >> 8) & 0xFF); // Key index MSB
            command.P2 = (byte)(keyIndex & 0xFF);        // Key index LSB
            command.Data = cryptogram;

            // Transceive
            RApdu response = Transcieve(command);

            // Parse and test status code
            if (response.IsError)
            {
                throw new Iso7816Exception(response.SW12, "PlaidLoadFAKey");
            }
        }


        #endregion

        #region "IDESFireSAM implementation"      

        byte[] IDESFireSAM.Authenticate0(short keyId, byte[] ekRndB)
        {
            DESFireKey key = (this as IDESFireSAM).FindKeyById(keyId);
            return EV1Authenticate0(key.SamIndex, ekRndB);
        }

        void IDESFireSAM.Authenticate1(byte[] ekRndA)
        {
            EV1Authenticate1(ekRndA);
        }

        byte[] IDESFireSAM.ChangeKey(byte keyNo, short newId, short? oldId)
        {

            if (oldId == null)
            {
                DESFireKey newKey = (this as IDESFireSAM).FindKeyById(newId);
                return EV1ChangeKey(keyNo, newKey.SamIndex, null);
            }
            else
            {
                DESFireKey newKey = (this as IDESFireSAM).FindKeyById(newId);
                DESFireKey oldKey = (this as IDESFireSAM).FindKeyById(oldId.Value);
                return EV1ChangeKey(keyNo, newKey.SamIndex, oldKey.SamIndex);
            }
        }

        byte[] IDESFireSAM.GenerateMAC(byte[] data)
        {
            return EV1GenerateMAC(data);
        }

        bool IDESFireSAM.VerifyMAC(byte[] data)
        {
            return EV1VerifyMAC(data);
        }

        byte[] IDESFireSAM.EncipherData(byte[] data)
        {
            return EV1EncipherData(data);
        }

        byte[] IDESFireSAM.DecipherData(byte[] data, byte expectedLength)
        {
            return EV1DecipherData(data, expectedLength);
        }

        void IDESFireSAM.UpdateIV(byte[] data)
        {
            EV1UpdateIV(data);
        }

        void IDESFireSAM.SetDivData(byte[] divData)
        {
            EV1SetDivData(divData);
        }

        DESFireKey IDESFireSAM.FindKeyById(short id)
        {
            foreach (PACSAMKey key in myKeys)
            {
                if (key.Id == id)
                {
                    DESFireKey result = new DESFireKey();
                    result.Id = key.Id;

                    if (key.KeyType == PACSAMKeyType.AES) result.KeyType = DESFireKeyType.AES;
                    else if (key.KeyType == PACSAMKeyType.DES) result.KeyType = DESFireKeyType.TDEA2KEY;
                    else
                    {
                        throw new InvalidOperationException();
                    }

                    result.Version = key.Version;
                    result.Name = key.Name;
                    result.SamIndex = key.Index;

                    return result;
                }
            }

            return null;
        }
        #endregion

        #region IPlaidSam implementation

        byte[] IPlaidSAM.InitialAuthenticate(short keyId, byte[] estr1, short opMode)
        {
            // Find the key
            PACSAMKey key = null;
            foreach (var k in myKeys)
            {
                if (k.Id == keyId && k.KeyType == PACSAMKeyType.PLAID) key = k;
            }
            if (null == key) throw new ArgumentException("keyId");

            return PlaidInitialAuthenticate(key.Index, estr1, opMode);
        }

        byte[] IPlaidSAM.FinalAuthenticate(byte[] estr3)
        {
            return PlaidFinalAuthenticate(estr3);
        }

        byte[] IPlaidSAM.SetData(byte[] commandObject)
        {
            return PlaidSetData(commandObject);
        }

        void IPlaidSAM.LoadFAKey(short keyId, byte[] cryptogram)
        {
            // Find the key
            PACSAMKey key = null;
            foreach (var k in myKeys)
            {
                if (k.Id == keyId && k.KeyType == PACSAMKeyType.PLAID)
                {
                    key = k;
                    break;
                }
            }
            if (null == key) throw new ArgumentException("keyId");

            PlaidLoadFAKey(key.Index, cryptogram);
        }

        public IEnumerator<PACSAMKey> GetEnumerator()
        {
            return ((IEnumerable<PACSAMKey>)myKeys).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable<PACSAMKey>)myKeys).GetEnumerator();
        }

        #endregion

        #region "Constants / Private Declarations"

        private const byte CLA = 0x00;

        #endregion
    }

    public enum SetDataElement
    {
        ESN = 1,
        PIN = 2,
        Profile = 3,
        SystemDiversifier = 4
    }
}
#endregion
