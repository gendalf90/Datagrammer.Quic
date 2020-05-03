using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CipherSuite
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private CipherSuite(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static CipherSuite Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 2);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(2);

            if(length > ushort.MaxValue - 2 || length > afterLengthBytes.Length || length % 2 == 1)
            {
                throw new EncodingException();
            }

            var bodyBytes = afterLengthBytes.Slice(0, length);

            remainings = afterLengthBytes.Slice(length);

            return new CipherSuite(bodyBytes);
        }

        public bool Intersect(CipherSuite other)
        {
            var currentBytes = bytes.Span;
            var otherBytes = other.bytes.Span;

            for(int i = 0, j = 0; i < currentBytes.Length && j < otherBytes.Length; i += 2, j += 2)
            {
                if(currentBytes[i] == otherBytes[j] && currentBytes[i + 1] == otherBytes[j + 1])
                {
                    return true;
                }
            }

            return false;
        }

        public static CipherSuite Supported { get; } = new CipherSuite(new byte[] { 13, 1 });

        public void WriteBytes(Span<byte> destination, out Span<byte> remainings)
        {
            if(destination.Length < 2)
            {
                throw new EncodingException();
            }

            NetworkBitConverter.WriteUnaligned(destination, (ulong)bytes.Length, 2);

            var afterLengthBytes = destination.Slice(2);

            if(!bytes.Span.TryCopyTo(afterLengthBytes))
            {
                throw new EncodingException();
            }

            remainings = afterLengthBytes.Slice(bytes.Length);
        }
    }
}
