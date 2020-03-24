using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketConnectionId : IEquatable<PacketConnectionId>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private PacketConnectionId(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketConnectionId version && Equals(version);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(bytes);
        }

        public bool Equals(PacketConnectionId other)
        {
            return bytes.Span.SequenceEqual(other.bytes.Span);
        }

        public static bool operator ==(PacketConnectionId first, PacketConnectionId second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketConnectionId first, PacketConnectionId second)
        {
            return !first.Equals(second);
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketConnectionId result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PacketConnectionId();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var length = bytes.Span[0];
            var afterLengthBytes = bytes.Slice(1);

            if (afterLengthBytes.Length < length)
            {
                return false;
            }

            var resultBytes = afterLengthBytes.Slice(0, length);

            result = new PacketConnectionId(resultBytes);
            remainings = afterLengthBytes.Slice(length);

            return true;
        }
    }
}
