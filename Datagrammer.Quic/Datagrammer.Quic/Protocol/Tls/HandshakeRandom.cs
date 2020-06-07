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

        public void WriteBytes(ref WritingCursor cursor)
        {
            if (!part1.TryWriteBytes(cursor.Destination))
            {
                throw new EncodingException();
            }

            var destinationOfPart2 = cursor.Destination.Slice(16);

            if (!part2.TryWriteBytes(destinationOfPart2))
            {
                throw new EncodingException();
            }

            cursor = cursor.Move(32);
        }

        public static HandshakeRandom Generate()
        {
            return new HandshakeRandom(Guid.NewGuid(), Guid.NewGuid());
        }
    }
}
