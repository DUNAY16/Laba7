using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Laba7
{
    class Cipher_RC2
    {
        public byte[] EncryptStringToBytes_RC2(
      byte[] plainText,
      byte[] Key,
      byte[] IV,
      CipherMode cipherMode = CipherMode.CBC,
      PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            if (Key == null || Key.Length == 0)
                throw new ArgumentNullException(nameof(Key));
            if (IV == null || IV.Length == 0)
                throw new ArgumentNullException(nameof(IV));
            byte[] array;
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Key = Key;
                rc2.IV = IV;
                rc2.Mode = cipherMode;
                rc2.Padding = paddingMode;
                ICryptoTransform encryptor = rc2.CreateEncryptor(rc2.Key, rc2.IV);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        //using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        //    streamWriter.Write(plainText);
                        //array = memoryStream.ToArray();
                        cryptoStream.Write(plainText, 0, plainText.Length);
                        cryptoStream.FlushFinalBlock();

                        array = memoryStream.ToArray();
                    }
                }
            }
            return array;
        }

        public byte[] DecryptStringFromBytes_RC2(
          byte[] cipherText,
          byte[] Key,
          byte[] IV,
          CipherMode cipherMode = CipherMode.CBC,
          PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (cipherText == null || cipherText.Length == 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (Key == null || Key.Length == 0)
                throw new ArgumentNullException(nameof(Key));
            if (IV == null || IV.Length == 0)
                throw new ArgumentNullException(nameof(IV));
            byte[] array;
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Key = Key;
                rc2.IV = IV;
                rc2.Mode = cipherMode;
                rc2.Padding = paddingMode;
                ICryptoTransform decryptor = rc2.CreateDecryptor(rc2.Key, rc2.IV);
                using (MemoryStream memoryStream = new MemoryStream(cipherText))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        //using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        //    str = streamReader.ReadToEnd();
                        //cryptoStream.Write(cipherText, 0, cipherText.Length);
                        //cryptoStream.FlushFinalBlock();

                        //array = memoryStream.ToArray();

                        array = new byte[cipherText.Length];
                        var bytesRead = cryptoStream.Read(array, 0, cipherText.Length);

                        array = array.Take(bytesRead).ToArray();
                    }
                }
            }
            return array;
        }
    }
}
