using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct NamedGroup : IEquatable<NamedGroup>
    {
        private readonly ushort code;

        private NamedGroup(ushort code)
        {
            this.code = code;
        }

        public static NamedGroup Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new NamedGroup(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            bytes = bytes.Slice(NetworkBitConverter.WriteUnaligned(bytes, code, 2));
        }

        public static NamedGroup SECP256R1 { get; } = new NamedGroup(0x0017);

        public static NamedGroup X25519 { get; } = new NamedGroup(0x001D);

        public bool Equals(NamedGroup other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is NamedGroup version && Equals(version);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(NamedGroup first, NamedGroup second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(NamedGroup first, NamedGroup second)
        {
            return !first.Equals(second);
        }
    }
}
