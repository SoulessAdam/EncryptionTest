using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace EncryptionTest
{
    class Program
    {
        public static void Main()
        {
            string a =
                "your shit script";
            using (Aes aes = new AesManaged())
            {
                // Implement this function to send off our key to a server and return our encrypted script
                byte[] encrypted = EncryptStringToBytes_Aes(a, aes.Key, aes.IV);

                // Decrypt the bytes returned from the function above to get out minified script
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, aes.Key, aes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine($"Original:   {a}");
                Console.WriteLine($"Decrypted: {roundtrip}");
            }
        }

        static byte[] EncryptStringToBytes_Aes(string original, Byte[] Key, Byte[] IV)
        {
            // Create out byte array for encrypted bytes. This is serverside...
            byte[] encryptedScript;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(original);
                        }

                        encryptedScript = msEncrypt.ToArray();
                    }
                }
            }
            // Send data back to client
            return encryptedScript;
        }

        static string DecryptStringFromBytes_Aes(byte[] encrypted, byte[] Key, byte[] IV)
        {
            // create a string for our minified script.
            string script = "";

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            script = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return script;
        }
    }
}