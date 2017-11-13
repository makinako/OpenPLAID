using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CardFramework.Applications.PACSAM
{
    public class PACSAMStatus
    {
        public const int SystemDivLength = 17; // 16 bytes + length byte
        public PACSAMAppletState AppletState;
        public ushort Profile;
        public uint ESN;
        public byte[] SystemDiversifier;
        public DESFireAuthStatus DESFireStatus;
        public PlaidAuthStatus PlaidStatus;

        // Returns true if the PIN has been successfully verified in this session
        public bool PINStatus;
    }

    public enum DESFireAuthStatus
    {
        AUTH_STATE_NONE = 0,

        AUTH_STATE_PHASE1_DES = 1,
        AUTH_STATE_PHASE1_ISO = 2,
        AUTH_STATE_PHASE1_AES = 3,
        AUTH_STATE_OK_DES = 4,
        AUTH_STATE_OK_ISO = 5,
        AUTH_STATE_OK_AES = 6
    }

    public enum PlaidAuthStatus
    {
        AUTH_STATE_NONE = 0,
        AUTH_STATE_IAKEY = 1,
        AUTH_STATE_OK = 2
    }

}
