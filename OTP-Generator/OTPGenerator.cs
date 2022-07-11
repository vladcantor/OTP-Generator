using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OTP_Generator
{
    /// <summary>
    /// TOTP implementation of <see href="https://www.rfc-editor.org/rfc/inline-errata/rfc6238.html"/>
    /// where the seeed is the userId.
    /// </summary>
    public class OTPGenerator
    {
        public const int Valid_Interval_Seconds = 30;

        private static readonly Encoding _encoding = new UTF8Encoding(false, true);

        /// <summary>
        /// Return Codes of 4 digits.
        /// </summary>
        public const int Number_Of_Digits = 10000;

        public static int GenerateTOTP(string userId, DateTime generationTime)
        {
            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if((generationTime - DateTime.UnixEpoch) <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(generationTime));
            }

            var timestepAsBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(GetExpirationTime(generationTime)));
            byte[] hash = HMACSHA1.HashData(_encoding.GetBytes(userId), timestepAsBytes);
            var offset = hash[hash.Length - 1] & 0xf;
            var binaryCode = (hash[offset] & 0x7f) << 24
                                | (hash[offset + 1] & 0xff) << 16
                                | (hash[offset + 2] & 0xff) << 8
                                | (hash[offset + 3] & 0xff);
            return binaryCode % Number_Of_Digits;
        }

        public static bool ValidateTOTP(int code, string userId, DateTime generationTime)
        {
            var expectedCode = GenerateTOTP(userId, generationTime);
            return expectedCode == code;
        }

        /// <summary>
        /// Get the time factor according to <see cref="RFC6238"/>
        /// </summary>
        /// <param name="generationTime"> When the token is generated.</param>
        /// <returns>The number of 30s intervals since Epoch.</returns>
        private static long GetExpirationTime(DateTime generationTime)
        {
            DateTimeOffset offset = generationTime.ToUniversalTime();
            long secondsSinceEpoch = offset.ToUnixTimeSeconds();
            long expirationTime = secondsSinceEpoch / Valid_Interval_Seconds;
            return expirationTime;
        }

    }
}