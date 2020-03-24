using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketRetryToken : IEquatable<PacketRetryToken>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        public PacketRetryToken(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketRetryToken version && Equals(version);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(bytes);
        }

        public bool Equals(PacketRetryToken other)
        {
            return bytes.Span.SequenceEqual(other.bytes.Span);
        }

        public static bool operator ==(PacketRetryToken first, PacketRetryToken second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketRetryToken first, PacketRetryToken second)
        {
            return !first.Equals(second);
        }
    }
}
