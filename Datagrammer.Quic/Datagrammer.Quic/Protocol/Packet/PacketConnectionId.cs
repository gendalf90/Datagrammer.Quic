using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketConnectionId : IEquatable<PacketConnectionId>
    {
        private const int MaxLength = 20;

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

        public static PacketConnectionId Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var length = bytes.Span[0];

            if(length > MaxLength)
            {
                throw new EncodingException();
            }

            var afterLengthBytes = bytes.Slice(1);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            var resultBytes = afterLengthBytes.Slice(0, length);

            remainings = afterLengthBytes.Slice(length);

            return new PacketConnectionId(resultBytes);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
