using CardFramework;
using CardFramework.Applications.PACSAM;
using CardFramework.Applications.Plaid;
using CardFramework.Readers.PCSC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PLAIDExample
{
    class Program
    {
        /// <summary>
        ///  Reference to our PCSC implementation
        /// </summary>
        static PCSCManager pcsc = new PCSCManager();

        /// <summary>
        /// The PCSC name of the reader that has the PACSAM token
        /// </summary>
        static string SamReader = @"Gemalto USB SmartCard Reader 0";

        /// <summary>
        /// The PCSC name of the reader that has a PLAID token
        /// </summary>
        static string TargetReader = @"HID Global OMNIKEY 5022 Smart Card Reader 0";

        static PCSCCard mySAM, myTarget;

        static void Main(string[] args)
        {
            // Hook events
            pcsc.OnReaderInserted += new EventHandler<PCSCReaderEventArgs>(reader_OnReaderInserted);
            pcsc.OnReaderRemoved += new EventHandler<PCSCReaderEventArgs>(reader_OnReaderRemoved);
            pcsc.OnCardInserted += new EventHandler<CardEventArgs>(reader_OnCardInserted);
            pcsc.OnCardRemoved += new EventHandler<CardEventArgs>(reader_OnCardRemoved);

            var readers = pcsc.ListReaders();

            if (!readers.Contains(SamReader))
            {
                Console.WriteLine($"SAM reader {SamReader} does not exist! Aborting ...");
                return;
            }

            if (!readers.Contains(TargetReader))
            {
                Console.WriteLine($"Target reader {TargetReader} does not exist! Aborting ...");
                return;
            }

            string msg = "PLAID Personalisation Demonstration:\n" +
                         "- Reader (SAM): " + SamReader + "\n" +
                         "- Reader (Target):  " + TargetReader + "\n\n" +
                         "WARNING: Confirm the above readers are correct and press enter to continue.";

            Console.Write(msg);
            Console.ReadLine();

            // Start polling
            pcsc.Connect();
            pcsc.Start();

            while (Console.ReadKey().Key != ConsoleKey.Q) Thread.Sleep(0);

            Console.WriteLine("Aborting the process.");

            // Stop polling
            pcsc.Stop();
            pcsc.Disconnect();
        }


        static void reader_OnReaderRemoved(object sender, PCSCReaderEventArgs e)
        {
            Console.WriteLine("PCSC> Reader removed '{0}'", e.Reader);
        }

        static void reader_OnReaderInserted(object sender, PCSCReaderEventArgs e)
        {
            Console.WriteLine("PCSC> Reader added '{0}'", e.Reader);
        }

        static void reader_OnCardRemoved(object sender, CardEventArgs e)
        {
            if (string.Equals(e.Reader, SamReader, StringComparison.CurrentCultureIgnoreCase))
            {
                mySAM = null;
                Console.WriteLine("PCSC> Token removed from reader '{0}' (SAM Reader)", e.Reader.ToString());
            }
            else if (string.Equals(e.Reader, TargetReader, StringComparison.CurrentCultureIgnoreCase))
            {
                myTarget = null;
                Console.WriteLine("PCSC> Token removed from reader '{0}' (Target Reader)", e.Reader.ToString());
            } else
            {
                Console.WriteLine("PCSC> Token removed from reader '{0}' (ignored)", e.Reader.ToString());
            }
        }

        static object insertedLock = new object(); 

        static void reader_OnCardInserted(object sender, CardEventArgs e)
        {
            lock (insertedLock)
            {
                if (string.Equals(e.Reader, SamReader, StringComparison.CurrentCultureIgnoreCase))
                {
                    mySAM = e.Card as PCSCCard;
                    Console.WriteLine("PCSC> Token inserted in reader '{0}' (SAM Reader)", e.Reader.ToString());
                    mySAM.Connect();
                }
                else if (string.Equals(e.Reader, TargetReader, StringComparison.CurrentCultureIgnoreCase))
                {
                    myTarget = e.Card as PCSCCard;
                    Console.WriteLine("PCSC> Token inserted in reader '{0}' (Target Reader)", e.Reader.ToString());
                    myTarget.Connect();
                }
                else
                {
                    Console.WriteLine("PCSC> Card inserted in reader '{0}' (ignored)", e.Reader.ToString());
                }

                // Check if we have both a SAM and a Target token
                if (mySAM == null || myTarget == null) return;
            }

            //
            // Personalise the SAM instance (if it has not been already personalised)
            //

            PACSAMApplication sam = null;

            try
            {
                var keyFile = PACSAMKeyFile.Load(@"PLAID_KEYS.xml", false);
                sam = new PACSAMApplication();
                sam.SetCard(mySAM);
                sam.SelectApplication();
                var status = sam.GetStatus();
                if (status.AppletState == PACSAMAppletState.Selectable)
                {
                    Console.WriteLine("SAM: Personalising ...");
                    sam.Personalise(0x11223344, "123456", keyFile);
                    Console.WriteLine("SAM: Personalisation complete ...");
                } else
                {
                    Console.WriteLine("SAM: Already personalised");
                }

                // Authenticate and list the keys (this also loads the key list internally)
                sam.VerifyPIN("123456");
                List<PACSAMKey> keys = sam.ReadAllKeys();
            } 
            catch (Exception ex)
            {
                Console.WriteLine("SAM: Error connecting, aborting ...", ex);
                return;
            }

            //
            // Personalise PLAID on the target card
            // 

            try
            {
                // Set the '$DYNAMIC$' parameter
                var parameters = new Dictionary<string, byte[]>();
                parameters.Add("$DYNAMIC$", "33333333333333333333333333333333".HexToArray());

                var template = PlaidTemplate.Load(@"PLAID_TEMPLATE.xml");
                var target = new PlaidApplication();
                target.SetCard(myTarget);

                target.OnMessage += (o, msg) => {
                    Console.WriteLine(@"PLAID: " + msg);
                };
                target.SelectApplication();
                target.Personalise(sam, template, parameters);

                Console.WriteLine("PLAID: Personalisation complete");

                byte[] op1 = target.Authenticate(sam, 0x0000, 0x6000, 0);
                Console.WriteLine("PLAID: Admin authenticated with OpMode 1: " + op1.ToHexString());
                byte[] op2 = target.Authenticate(sam, 0x0000, 0x6000, 1);
                Console.WriteLine("PLAID: Admin authenticated with OpMode 2: " + op2.ToHexString());
                byte[] op3 = target.Authenticate(sam, 0x0000, 0x6000, 2);
                Console.WriteLine("PLAID: Admin authenticated with OpMode 3: " + op3.ToHexString());

                Console.WriteLine("Personalisation complete (remove card)");
            }
            catch (Exception ex)
            {
                Console.WriteLine("PLAID: Error during personalisation, aborting ...", ex);
                return;
            }
        }
    }
}
