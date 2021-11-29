using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Laba7
{
    class KeyGen
    {
        static public byte[] generator_Key(int lenKey, string numKey = "з нулями")
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            byte[] randomArray = new byte[lenKey];

            switch (numKey)
            {
                case "з нулями":
                    rng.GetBytes(randomArray);
                    break;
                case "без нулів":
                    rng.GetNonZeroBytes(randomArray);
                    break;
                default:
                    // проблема
                    break;
            }

            return randomArray;
        }
    }
}
