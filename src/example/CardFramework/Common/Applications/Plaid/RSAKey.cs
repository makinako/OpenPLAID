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
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.IO;

namespace CardFramework.Applications.Plaid
{
    public class RSAKey
    {
        public RSAKey()
        {

        }

        public RSAKey(RSAKey copyObject)
        {
            copyObject.Clone(this);
        }

        public RSAKey(RSAParameters parameters)
        {
            P = parameters.P;
            Q = parameters.Q;
            PQ = parameters.InverseQ;
            DP = parameters.DP;
            DQ = parameters.DQ;
            D = parameters.D;
            Modulus = parameters.Modulus;
            Exponent = parameters.Exponent;
        }

        public RSAKey(byte[] modulus, byte[] exponent = null)
        {
            Modulus = modulus.ToArray();
            Exponent = (exponent == null) ? DefaultExponent : exponent.ToArray();
        }

        public void Clone (RSAKey to)
        {
            to.P = P.ToArray();
            to.Q = Q.ToArray();
            to.PQ = PQ.ToArray();
            to.DP = DP.ToArray();
            to.DQ = DQ.ToArray();
            to.D = D.ToArray();
            to.Modulus = Modulus.ToArray();
            to.Exponent = Exponent.ToArray();
        }

        public byte[] GetHashInputData()
        {
            MemoryStream s = new MemoryStream();

            if (P != null) s.Write(P, 0, P.Length);
            if (Q != null) s.Write(Q, 0, Q.Length);
            if (PQ != null) s.Write(PQ, 0, PQ.Length);
            if (DP != null) s.Write(DP, 0, DP.Length);
            if (DQ != null) s.Write(DQ, 0, DQ.Length);
            if (D != null) s.Write(D, 0, D.Length);
            if (Modulus != null) s.Write(Modulus, 0, Modulus.Length);
            if (Exponent != null) s.Write(Exponent, 0, Exponent.Length);

            return s.ToArray();
        }

        public static readonly byte[] DefaultExponent = new byte[] { 0x01, 0x00, 0x01 };

        [XmlElement(DataType = "hexBinary")]
        public byte[] P { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] Q { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] PQ { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] DP { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] DQ { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] D { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] Modulus { get; set; }

        [XmlElement(DataType = "hexBinary")]
        public byte[] Exponent { get; set; }
    }
}
