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
using System.IO;
using CardFramework.Helpers;
using System.Diagnostics;

namespace CardFramework.Protocols.Iso7816
{
    /// <summary>
    /// Helper class that imports the 'Ludovic Rousseau' ATR listing into our format.
    /// </summary>
    public class AtrListImporter
    {
        public static void Parse(string path)
        {
            StreamReader reader = new StreamReader(path);
            Iso7816DiscoveryDataCollection data = new Iso7816DiscoveryDataCollection();

            string line;
            while ((line = reader.ReadLine()) != null)
            {
                // Check if we should skip
                if (string.IsNullOrEmpty(line)) continue;
                if (line.StartsWith(@"#")) continue;

                if (IsAtr(line))
                {
                    string atr = line;
                    string description = @"";
                    while ((line = reader.ReadLine()) != null)
                    {
                        // Have we reached whitespace? That's the end of this record
                        if (string.IsNullOrEmpty(line)) break;
                        description += string.Format("{0}, ", line.Trim());
                    }

                    Iso7816DiscoveryData entry = new Iso7816DiscoveryData(atr, description);
                    data.Add(entry);
                    Debug.WriteLine(string.Format("{0}\n{1}", atr, description));
                }
            }

            Serialiser<Iso7816DiscoveryDataCollection>.Save(@"Iso7816DiscoveryData.Xml", data);
        }

        private static bool IsAtr(string line)
        {
            foreach (char c in line)
            {
                // We skip whitespace, allow hex characters and also the period '.' for the wildcard
                if (char.IsWhiteSpace(c)) continue;
                if (!Converters.IsHexChar(c) && c != '.') return false;
            }
            return true;
        }
    }
}
