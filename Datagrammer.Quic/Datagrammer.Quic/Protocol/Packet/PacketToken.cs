using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketToken : IEquatable<PacketToken>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        public PacketToken(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketToken version && Equals(version);
        }

        public override int GetHashCode()
        {
            return HashCodeCalculator.Calculate(bytes.Span);
        }

        public bool Equals(PacketToken other)
        {
            return bytes.Span.SequenceEqual(other.bytes.Span);
        }

        public static bool operator ==(PacketToken first, PacketToken second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketToken first, PacketToken second)
        {
            return !first.Equals(second);
        }

        public static PacketToken Empty { get; } = new PacketToken();

        public static PacketToken Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var tokenLength = VariableLengthEncoding.Decode32(bytes.Span, out var decodedBytesLength);
            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if (afterLengthBytes.Length < tokenLength)
            {
                throw new EncodingException();
            }

            var tokenBytes = afterLengthBytes.Slice(0, tokenLength);

            remainings = afterLengthBytes.Slice(tokenLength);

            return new PacketToken(tokenBytes);
        }

        public void WriteBytes(Span<byte> destination, out Span<byte> remainings)
        {
            VariableLengthEncoding.Encode(destination, (ulong)bytes.Length, out var encodedLength);

            var afterLengthBytes = destination.Slice(encodedLength);

            if (!bytes.Span.TryCopyTo(afterLengthBytes))
            {
                throw new EncodingException();
            }

            remainings = afterLengthBytes.Slice(bytes.Length);
        }
    }
}
