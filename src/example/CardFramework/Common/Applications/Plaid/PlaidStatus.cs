using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CardFramework.Applications.Plaid
{
    public enum PlaidAppletState
    {
        Selectable = 0x00,
        Personalised = 0x01,
        Blocked = 0x02,
        Terminated = 0x80
    }

    public enum PlaidAuthState
    {
        None = 0x00,
        IAKey = 0x01,
        OK = 0x02
    }

    public class PlaidStatus
    {
        public PlaidStatus()
        {

        }

        public PlaidStatus(byte[] status)
        {
            AppletState = (PlaidAppletState)status[0];
            AuthState = (PlaidAuthState)status[1];
        }

        public PlaidAppletState AppletState;
        public PlaidAuthState AuthState;
    }
}
