using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionTest
{
    internal class Program
    {
        public static void Main()
        {
            var a = "MinifiedScriptGoesHereCouldEvenUseJSFUCK?";
            using (Aes aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.Key = Encoding.UTF8.GetBytes(
                    "FakeKeyForSendingToTheServerFun!"); /* Randomise on each login? Idk if we should use static keys, I see no reason not too but tbh idrc */
                /* ^ Segment this serverside? Prevent MITM key stealing ig, more secure, client knows key, server knows key but only part of key is used, could even
                 BASE64 encode this incase too. -- Edit I have implemented this below, we can use this to secure our keys and make cracking this shit a pain
                 They'd have to first B64 decode the key, then try replicate out segments from our key. The actual key is never seen in plain text yet its easy for
                 us to use it. IDK why I even went about it this way but its the simplest way I could come up with to share keys and not have it comped. Without a load of security shit
                 that I don't understand, we need to obfuscate and pack all of this shit too.  */
                // Implement this function to send off our key to a server and return our encrypted script
                var base64Key = Convert.ToBase64String(aes.Key);
                var encrypted = EncryptStringToBytes_Aes(a, base64Key, aes.IV);
                // Decrypt the bytes returned from the function above to get out minified script
                var decryted = DecryptStringFromBytes_Aes(encrypted, base64Key, aes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine($"Original:  {a}");
                Console.WriteLine($"Decrypted: {decryted}");
            }
        }

        private static byte[] EncryptStringToBytes_Aes(string original, string Base64Key, byte[] IV)
        {
            // This  would be serverside...
            byte[] encryptedScript;
            using (var aesAlg = new AesManaged())
            {
                var Key = Convert.FromBase64String(Base64Key);
                byte[] actualKey =
                {
                    Key[1], Key[3], Key[5], Key[16], Key[4], Key[2], Key[5], Key[1], Key[8], Key[31], Key[21], Key[16],
                    Key[13], Key[15], Key[13], Key[0]
                };
                aesAlg.KeySize = 128;
                aesAlg.Key = actualKey;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
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

        private static string DecryptStringFromBytes_Aes(byte[] encrypted, string Base64Key, byte[] IV)
        {
            // create a string for our minified script.
            var script = "";

            using (var aesAlg = new AesManaged())
            {
                var Key = Convert.FromBase64String(Base64Key);
                byte[] actualKey =
                {
                    Key[1], Key[3], Key[5], Key[16], Key[4], Key[2], Key[5], Key[1], Key[8], Key[31], Key[21], Key[16],
                    Key[13], Key[15], Key[13], Key[0]
                };
                aesAlg.Key = actualKey;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (var msDecrypt = new MemoryStream(encrypted))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
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
