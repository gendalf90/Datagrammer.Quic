using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketToken : IEquatable<PacketToken>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        internal PacketToken(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketToken version && Equals(version);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(bytes);
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

        public static PacketToken Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

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
    }
}
