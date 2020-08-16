using System;
using System.Globalization;
using System.Text;

namespace Tests
{
    public static class Utils
    {
        public static byte[] ParseHexString(string str)
        {
            if (str.Length % 2 != 0)
            {
                throw new ArgumentException(nameof(str));
            }

            var chars = str.AsSpan();
            var bytes = new byte[str.Length / 2];

            for(int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(chars.Slice(i * 2, 2), NumberStyles.HexNumber);
            }

            return bytes;
        }

        public static string ToHexString(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);

            foreach (var b in bytes)
            {
                result.Append(b.ToString("X2"));
            }

            return result.ToString();
        }
    }
}
