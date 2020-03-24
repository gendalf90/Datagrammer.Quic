using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketVersion : IEquatable<PacketVersion>
    {
        private readonly int version;

        private PacketVersion(int version)
        {
            this.version = version;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketVersion version && Equals(version);
        }

        public override int GetHashCode()
        {
            return version;
        }

        public bool Equals(PacketVersion other)
        {
            return version == other.version;
        }

        public static bool operator ==(PacketVersion first, PacketVersion second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketVersion first, PacketVersion second)
        {
            return !first.Equals(second);
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketVersion result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PacketVersion();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (bytes.Length < 4)
            {
                return false;
            }

            var versionBytes = bytes.Slice(0, 4);
            var version = BitConverter.ToInt32(versionBytes.Span);

            result = new PacketVersion(version);
            remainings = bytes.Slice(4);

            return true;
        }
    }
}
