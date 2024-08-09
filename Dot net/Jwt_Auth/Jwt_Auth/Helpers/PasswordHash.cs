using System.Security.Cryptography;

namespace Jwt_Auth.Helpers
{
    public class PasswordHash
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HashSize = 20;
        private static readonly int Iteration = 10000;

        public static string HashPassword(string password)
        {
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);

            var key = new Rfc2898DeriveBytes(password, salt, Iteration);
            var hash = key.GetBytes(HashSize);

            var hashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

            // Convert the entire byte array (salt + hash) to a Base64 string
            var base64Hash = Convert.ToBase64String(hashBytes);

            // Debug: Print the base64Hash length
            Console.WriteLine($"HashPassword - Base64 Hash Length: {base64Hash.Length}");

            return base64Hash;
        }

        public static bool VerifyPassword(string password, string base64Hash)
        {
            try
            {
                var hashBytes = Convert.FromBase64String(base64Hash);

                // Debug: Print the length of the hashBytes array
                Console.WriteLine($"VerifyPassword - HashBytes Length: {hashBytes.Length}");

                // Ensure the length of hashBytes is at least SaltSize + HashSize
                if (hashBytes.Length != SaltSize + HashSize)
                {
                    throw new ArgumentException("Invalid hash length.");
                }

                var salt = new byte[SaltSize];
                Array.Copy(hashBytes, 0, salt, 0, SaltSize);

                var key = new Rfc2898DeriveBytes(password, salt, Iteration);
                byte[] hash = key.GetBytes(HashSize);

                for (int i = 0; i < HashSize; i++)
                {
                    if (hashBytes[i + SaltSize] != hash[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during password verification: {ex.Message}");
                return false;
            }
        }
    }

}

