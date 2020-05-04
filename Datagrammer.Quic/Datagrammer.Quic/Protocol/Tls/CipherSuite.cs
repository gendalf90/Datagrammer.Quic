using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private static byte[] TLS_AES_128_GCM_SHA256 = new byte[] { 13, 1 };

        private readonly ReadOnlyMemory<byte> bytes;

        private CipherSuite(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 2..ushort.MaxValue, out bytes);

            if (data.Length % 2 == 1)
            {
                throw new EncodingException();
            }

            remainings = bytes;

            return new CipherSuite(data);
        }

        public bool Intersect(CipherSuite other)
        {
            var currentBytes = bytes.Span;
            var otherBytes = other.bytes.Span;

            for(int i = 0; i < currentBytes.Length; i += 2)
            {
                for(int j = 0; j < otherBytes.Length; j += 2)
                {
                    if (currentBytes[i] == otherBytes[j] && currentBytes[i + 1] == otherBytes[j + 1])
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static CipherSuite Supported { get; } = new CipherSuite(TLS_AES_128_GCM_SHA256);

        public int WriteBytes(Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(destination);

            if (!bytes.Span.TryCopyTo(context.Current))
            {
                throw new EncodingException();
            }

            context.Move(bytes.Length);

            return ByteVector.FinishVectorWriting(context, 2..ushort.MaxValue);
        }
    }
}
