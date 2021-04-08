﻿using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Linq;

namespace EncryptionTest
{
    class Program
    {
        public static void Main()
        {
            string a = "MinifiedScriptGoesHereCouldEvenUseJSFUCK?";
            using (Aes aes = new AesManaged())
            {
                aes.KeySize = 256;
                Console.WriteLine(aes.KeySize);
                aes.Key = System.Text.Encoding.UTF8.GetBytes("FakeKeyForSendingToTheServerFun!"); /* RANDOMISE ON ACCOUNT CREATION, STORE IN DB, HAVE SENT ON LOGIN. LOAD INTO MEM TO ENCODE THEN WIPE!*/
                /* ^ Segment this serverside? Prevent MITM key stealing ig, more secure, client knows key, server knows key but only part of key is used, could even
                 BASE64 encode this incase too. -- Edit I have implemented this below, we can use this to secure our keys and make cracking this shit a pain
                 They'd have to first B64 decode the key, then try replicate out segments from our key. The actual key is never seen in plain text yet its easy for
                 us to use it. IDK why I even went about it this way but its the simplest way I could come up with to share keys and not have it comped. Without a load of security shit
                 that I don't understand, we need to obfuscate and pack all of this shit too.  */
                Console.WriteLine(aes.Key.Length);
                // Implement this function to send off our key to a server and return our encrypted script
                string base64Key = Convert.ToBase64String(aes.Key);
                byte[] encrypted = EncryptStringToBytes_Aes(a, base64Key, aes.IV);
                // Decrypt the bytes returned from the function above to get out minified script
                string decryted = DecryptStringFromBytes_Aes(encrypted, base64Key, aes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine($"Original:  {a}");
                Console.WriteLine($"Decrypted: {decryted}");
            }
        }

        static byte[] EncryptStringToBytes_Aes(string original, string Base64Key, byte[] IV)
        {
            // This  would be serverside...
            byte[] encryptedScript;
            using (AesManaged aesAlg = new AesManaged())
            {
                var Key = Convert.FromBase64String(Base64Key);
                Byte[] actualKey = {Key[1], Key[3], Key[5], Key[16], Key[4], Key[2], Key[5], Key[1], Key[8], Key[31], Key[21], Key[16], Key[13], Key[15], Key[13], Key[0]};
                aesAlg.KeySize = 128;
                aesAlg.Key = actualKey;
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

        static string DecryptStringFromBytes_Aes(byte[] encrypted, string Base64Key, byte[] IV)
        {
            // create a string for our minified script.
            string script = "";

            using (AesManaged aesAlg = new AesManaged())
            {
                byte[] Key = Convert.FromBase64String(Base64Key);
                Byte[] actualKey = {Key[1], Key[3], Key[5], Key[16], Key[4], Key[2], Key[5], Key[1], Key[8], Key[31], Key[21], Key[16], Key[13], Key[15], Key[13], Key[0]};
                aesAlg.Key = actualKey;
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