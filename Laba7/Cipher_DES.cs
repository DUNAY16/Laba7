using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Laba7
{
    class Cipher_DES
    {
        public byte[] EncryptStringToBytes(
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
                throw new ArgumentNullException(nameof(Key));
            byte[] array;
            using (DES des = DES.Create())
            {
                des.Key = Key;
                des.IV = IV;
                des.Mode = cipherMode;
                des.Padding = paddingMode;
                ICryptoTransform encryptor = des.CreateEncryptor(des.Key, des.IV);
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

        public byte[] DecryptStringFromBytes(
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
                throw new ArgumentNullException(nameof(Key));
            byte[] array;
            using (DESCryptoServiceProvider cryptoServiceProvider = new DESCryptoServiceProvider())
            {
                cryptoServiceProvider.Key = Key;
                cryptoServiceProvider.IV = IV;
                cryptoServiceProvider.Mode = cipherMode;
                cryptoServiceProvider.Padding = paddingMode;
                ICryptoTransform decryptor = cryptoServiceProvider.CreateDecryptor(cryptoServiceProvider.Key, cryptoServiceProvider.IV);
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
