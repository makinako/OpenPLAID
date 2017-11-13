using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework.Applications.DESFire
{
    public interface IDESFireSAM
    {
        byte[] Authenticate0(short keyId, byte[] ekRndB);
        void Authenticate1(byte[] ekRndA);
        byte[] ChangeKey(byte keyNo, short newId, short? oldId = null);
        byte[] GenerateMAC(byte[] data);
        bool VerifyMAC(byte[] data);
        byte[] EncipherData(byte[] data);
        byte[] DecipherData(byte[] data, byte expectedLength = 0);
        void UpdateIV(byte[] data);
        void SetDivData(byte[] divData);
        DESFireKey FindKeyById(short id);
    }
}
