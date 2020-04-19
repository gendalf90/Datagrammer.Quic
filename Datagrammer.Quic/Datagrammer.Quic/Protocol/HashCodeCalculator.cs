using System;

namespace Datagrammer.Quic.Protocol
{
    internal static class HashCodeCalculator
    {
        public static int Calculate(ReadOnlySpan<byte> bytes)
        {
            unchecked
            {
                if(bytes.IsEmpty)
                {
                    return 0;
                }

                var hash = 17;

                for(int i = 0; i < bytes.Length; i++)
                {
                    hash = hash * 31 + bytes[i];
                }

                return hash;
            }
        }
    }
}
