using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.Security.Cryptography;

namespace KeyLake
{
    public class CryptoIO
    {
        public static byte[] CreateRandBytes(int bytes)
        {
            var buffer = new byte[bytes];
            var generator = RandomNumberGenerator.Create();
            generator.GetBytes(buffer);
            return buffer;
        }
        public static async Task<SymmetricSecurityKey> CreateKey(string id, byte[] bytes)
        {
            var key = new SymmetricSecurityKey(bytes)
            {
                KeyId = id
            };
            await File.WriteAllBytesAsync($"keys/{id}.key", bytes);
            return key;
        }
        public static async Task<SymmetricSecurityKey> GetKey(string id)
        {
            var bytes = await File.ReadAllBytesAsync($"keys/{id}.key");
            var key = new SymmetricSecurityKey(bytes)
            {
                KeyId = id
            };
            return key;
        }
        public static bool DeleteKey(string id)
        {
            try
            {
                File.Delete($"keys/{id}.key");
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
