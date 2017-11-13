# OpenPLAIDExample

This project requires:
- Visual Studio 2015 Community Edition or higher
- 2 x PCSC Smartcard Readers (at least one of them contact)
- 1 x Dual Interface smartcard token loaded with the OpenPLAID applet
- 1 x Contact (or Dual) smartcard token loaded with the OpenPLAIDSAM applet

Steps to execute:
1. Load the project into Visual Studio 2015
2. Ensure that the **SAMReader** and **TargetReader** constants are set to match your PC/SC readers
3. Compile and run (suggest in *Debug* configuration to allow step-through)
4. Insert the token with the OpenPLAIDSAM applet into the contact reader (it will not permit itself to be used over contactless)
5. Insert the token with the OpenPLAID applet into the other contact/contactless reader
6. The application will automatically detect both tokens and begin the process

### Example Notes

* The file *PLAID_KEYS.Xml* contains the PLAID test keyset
* The Modulus value for the key *PLAID_TRANSPORT* is also included in the OpenPLAID applet.
* If the SAM has never been personalised before, it will automatically be personalised using the *PLAID_KEYS.xml* data.
* The file *PLAID_TEMPLATE.Xml* contains an example PLAID personalisation profile with 3 ACSRecords and 3 keysets.
