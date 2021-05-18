using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ImageStorage
{
    internal class Program
    {
        private static string Key = "TheDefaultKeyPleaseOverwriteThis";

        // private static string Mode;
        private static int FileCount;

        private static async Task Main(string[] args)
        {
            await Startup.checkDir();
            await Task.Delay(1250);
            // FileCount = Directory.EnumerateFiles(Settings.savePath).ToArray().Length;
            Key = args[1];
            EncryptImages();
            // CHECK MODES FOR DECRYPT WHEN DONE
        }

        private static Image[] EnumerateImages()
        {
            var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            var files = dir.GetFiles("*.png");
            var images = new List<Image>();
            foreach (var image in files) images.Add(Image.FromFile(image.FullName));

            return images.ToArray();
        }

        private static FileInfo[] EnumerateEncrypts()
        {
            var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            var files = dir.GetFiles("*.ae");
            return files;
            // TODO: FINISH OFF DECRYPTING FOR INBUILT IMAGE VIEWING. CONVERT TO WINFORMS/WPF AT SOME POINT
        }

        private static void EncryptImages()
        {
            foreach (var image in EnumerateImages())
                using (var m = new MemoryStream())
                {
                    image.Save(m, image.RawFormat);
                    EncryptBytes(m.ToArray());
                }
        }

        private static async void EncryptBytes(byte[] bytes)
        {
            using (var aesAlg = new AesManaged())
            {
                aesAlg.KeySize = 256;
                aesAlg.Key = Encoding.UTF8.GetBytes(Key);

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(bytes);
                        }

                        await SaveImage(msEncrypt.ToArray(), $"{FileCount}.ae");
                        FileCount += 1;
                    }
                }
            }
        }

        private static Task SaveImage(byte[] encryptedBytes, string name = "you fucked up.ae")
        {
            File.WriteAllBytes($"{Settings.savePath}/{name}", encryptedBytes);
            return Task.CompletedTask;
        }
    }
}