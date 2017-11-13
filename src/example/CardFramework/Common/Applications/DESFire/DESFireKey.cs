using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework.Applications.DESFire
{
    public enum DESFireKeyType : byte
    {
        TDEA2KEY = 0x00,
        TDEA3KEY = 0x40, // 0x01 shifted to the top 2 msbit
        AES = 0x80 // 0x10 shifted to the top 2 msbits
    }

    public class DESFireKey
    {
        public short Id; // The key identifier

        //public byte[] Value;
        public byte Version;
        public DESFireKeyType KeyType;
        public string Name;

        public short SamIndex; // The index as known by the IDESFireSAM implementation
    }
}
