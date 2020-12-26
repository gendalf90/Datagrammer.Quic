using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls.Curves;
using System;
using System.Collections.Generic;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct NamedGroup : IEquatable<NamedGroup>
    {
        private static NamedGroup[] supported = new[] { X25519 };

        private static Dictionary<ushort, ICurve> curves = new Dictionary<ushort, ICurve>
        {
            [0x001D] = new X25519()
        };

        private readonly ushort code;

        private NamedGroup(ushort code)
        {
            this.code = code;
        }

        public static NamedGroup Parse(MemoryCursor cursor)
        {
            var codeBytes = cursor.Move(2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            return new NamedGroup(code);
        }

        public static NamedGroup Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new NamedGroup(code);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2);

            NetworkBitConverter.WriteUnaligned(bytes.Span, code, 2);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            bytes = bytes.Slice(NetworkBitConverter.WriteUnaligned(bytes, code, 2));
        }

        public static NamedGroup X25519 { get; } = new NamedGroup(0x001D);

        public static NamedGroup SECP256R1 { get; } = new NamedGroup(0x0017);

        public static NamedGroup SECP384R1 { get; } = new NamedGroup(0x0018);

        public static ReadOnlyMemory<NamedGroup> Supported => supported;

        public ICurve GetCurve()
        {
            if (curves.TryGetValue(code, out var curve))
            {
                return curve;
            }

            throw new NotSupportedException();
        }

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
