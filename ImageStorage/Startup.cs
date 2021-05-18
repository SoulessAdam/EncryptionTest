using System.IO;
using System.Threading.Tasks;

namespace ImageStorage
{
    public class Startup
    {
        public static async Task<Task> checkDir()
        {
            if (!Directory.Exists(Settings.savePath))
            {
                await Task.Run(() => Directory.CreateDirectory(Settings.savePath));
                return Task.CompletedTask;
            }

            return Task.CompletedTask;
        }
    }
}