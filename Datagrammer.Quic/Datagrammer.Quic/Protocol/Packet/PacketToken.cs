using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketToken : IEquatable<PacketToken>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private PacketToken(ReadOnlyMemory<byte> bytes)
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

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketToken result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PacketToken();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!VariableLengthEncoding.TryDecode32(bytes.Span, out var tokenLength, out var decodedBytesLength))
            {
                return false;
            }

            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if (afterLengthBytes.Length < tokenLength)
            {
                return false;
            }

            var tokenBytes = afterLengthBytes.Slice(0, tokenLength);

            result = new PacketToken(tokenBytes);
            remainings = afterLengthBytes.Slice(tokenLength);

            return true;
        }
    }
}
