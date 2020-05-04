using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct HandshakeRandom
    {
        private readonly Guid part1;
        private readonly Guid part2;

        private HandshakeRandom(Guid part1, Guid part2)
        {
            this.part1 = part1;
            this.part2 = part2;
        }

        public static HandshakeRandom Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 32)
            {
                throw new EncodingException();
            }

            var bytesOfPart1 = bytes.Slice(0, 16);
            var bytesOfPart2 = bytes.Slice(16, 16);

            remainings = bytes.Slice(32);

            return new HandshakeRandom(new Guid(bytesOfPart1.Span), new Guid(bytesOfPart2.Span));
        }

        public int WriteBytes(Span<byte> bytes)
        {
            var destinationOfPart1 = bytes;

            if(!part1.TryWriteBytes(destinationOfPart1))
            {
                throw new EncodingException();
            }

            var destinationOfPart2 = destinationOfPart1.Slice(16);

            if (!part2.TryWriteBytes(destinationOfPart2))
            {
                throw new EncodingException();
            }

            return 32;
        }

        public static HandshakeRandom Generate()
        {
            return new HandshakeRandom(Guid.NewGuid(), Guid.NewGuid());
        }
    }
}
