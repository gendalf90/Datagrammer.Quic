using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketRetryIntegrityTag : IEquatable<PacketRetryIntegrityTag>
    {
        private readonly Guid value;

        private PacketRetryIntegrityTag(Guid value)
        {
            this.value = value;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketRetryIntegrityTag version && Equals(version);
        }

        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        public bool Equals(PacketRetryIntegrityTag other)
        {
            return value == other.value;
        }

        public static bool operator ==(PacketRetryIntegrityTag first, PacketRetryIntegrityTag second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketRetryIntegrityTag first, PacketRetryIntegrityTag second)
        {
            return !first.Equals(second);
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketRetryIntegrityTag result, out ReadOnlyMemory<byte> bytesBefore)
        {
            result = new PacketRetryIntegrityTag();
            bytesBefore = ReadOnlyMemory<byte>.Empty;

            if (bytes.Length < 16)
            {
                return false;
            }
            
            var tagBytes = bytes.Slice(bytes.Length - 16, 16);
            var tagValue = new Guid(tagBytes.Span);

            result = new PacketRetryIntegrityTag(tagValue);
            bytesBefore = bytes.Slice(0, bytes.Length - 16);

            return true;
        }
    }
}
