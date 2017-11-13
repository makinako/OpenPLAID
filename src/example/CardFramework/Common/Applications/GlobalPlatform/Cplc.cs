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
using CardFramework;
using CardFramework.Helpers;

namespace CardFramework.Applications.GlobalPlatform
{
    /*
     * TODO: Find the authorative source of this info, GlobalPlatform no longer supports it.
     * 
     * - Obtained from: http://www.mail-archive.com/opencard@opencard.org/msg01101.html
     * 
     * 5 ROM identifiers (10 bytes), each consisting of 4 digits coded on 2 bytes:
     * -  IC Fabricator (2B)
     * -  IC Type (2B)
     * -  Operating System Provider Identifier (2B)
     * -  Operating System Release Date (2B)
     * -  Operating System Release Level (2B)

     * EEPROM Identifiers contain chip, card, pre-perso & personalizer info., in the given order :
     * -  Chip Identifiers:
     * -  IC Fabrication Date (2B)
     * -  IC Serial Number (4B)
     * -  IC Batch Identifier (2B) 

     * -  Card identifiers :
     * -  IC Module Fabricator  (2B)
     * -  IC Module Packaging Date      (2B)
     * -  ICC Manufacturer      (2B)
     * -  IC Embedding date     (2B)

     * -  Pre-personalization identifiers :
     * -  Pre-personalizer Identifier (2B)
     * -  Pre-personalization Date (2B)
     * -  Pre-personalization Equipment (4B)

     * -  Personalization identifiers :
     * -  Personalizer Identifier (2B)
     * -  Personalization Date (2B)
     * -  Personalization Equipment (4B)   
     * 
     */
    public class Cplc
    {
        public const int CplcLength = 42;

        public Cplc()
        {

        }

        public Cplc(byte[] cplc)
        {

        }

        public int ICFabricator { get; set; }
        public int ICType { get; set; }
        public int OSProviderId { get; set; }
        public int OSReleaseDate { get; set; }
        public int OSReleaseLevel { get; set; }
        public int ICFabricationDate { get; set; }
        public uint ICSerialNo { get; set; }
        public int ICBatchId { get; set; }
        public int ICModuleFabricator { get; set; }
        public int ICModulePackagingDate { get; set; }
        public int ICCManufacturer { get; set; }
        public int ICEmbeddingDate { get; set; }
        public int PrePersoId { get; set; }
        public int PrePersoDate { get; set; }
        public int PrePersoEquipment { get; set; }
        public int PersoId { get; set; }
        public int PersoDate { get; set; }
        public int PersoEquipment { get; set; }

        public static Cplc Parse(byte[] cplc)
        {
            if (cplc == null) throw new NullReferenceException();
            if (cplc.Length != CplcLength) throw new InvalidOperationException("CPLC length mismatch");

            BinaryParser parser = new BinaryParser(cplc, ByteEndianess.BigEndian, BitEndianess.Msb);
            Cplc output = new Cplc();

            /*
             * 5 ROM identifiers (10 bytes), each consisting of 4 digits coded on 2 bytes:
             */

            // -  IC Fabricator (2B)
            output.ICFabricator = parser.ReadUInt16();

            // -  IC Type (2B)
            output.ICType = parser.ReadUInt16();

            // -  Operating System Provider Identifier (2B)
            output.OSProviderId = parser.ReadUInt16();

            // -  Operating System Release Date (2B)
            output.OSReleaseDate = parser.ReadUInt16();

            // -  Operating System Release Level (2B)
            output.OSReleaseLevel = parser.ReadUInt16();

            /*
             * EEPROM Identifiers contain chip, card, pre-perso & personalizer info., in the given order :
             */

            // -  Chip Identifiers:
            // -  IC Fabrication Date (2B)
            output.ICFabricationDate = parser.ReadUInt16();

            // -  IC Serial Number (4B)
            output.ICSerialNo = parser.ReadUInt32();

            // -  IC Batch Identifier (2B)
            output.ICBatchId = parser.ReadUInt16();

            // -  Card identifiers :
            // -  IC Module Fabricator  (2B)
            output.ICModuleFabricator = parser.ReadUInt16();

            // -  IC Module Packaging Date      (2B)
            output.ICModulePackagingDate = parser.ReadUInt16();

            // -  ICC Manufacturer      (2B)
            output.ICCManufacturer = parser.ReadUInt16();

            // -  IC Embedding date     (2B)
            output.ICEmbeddingDate = parser.ReadUInt16();

            // -  Pre-personalization identifiers :
            // -  Pre-personalizer Identifier (2B)
            output.PrePersoId = parser.ReadUInt16();

            // -  Pre-personalization Date (2B)
            output.PrePersoDate = parser.ReadUInt16();

            // -  Pre-personalization Equipment (4B)
            output.PrePersoEquipment = parser.ReadUInt16();

            // -  Personalization identifiers :
            // -  Personalizer Identifier (2B)
            output.PersoId = parser.ReadUInt16();

            // -  Personalization Date (2B)
            output.PersoDate = parser.ReadUInt16();

            // -  Personalization Equipment (4B)   
            output.PersoEquipment = parser.ReadUInt16();

            return output;
        }
    }
}
