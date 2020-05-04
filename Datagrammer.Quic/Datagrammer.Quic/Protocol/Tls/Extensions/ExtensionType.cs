using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct ExtensionType : IEquatable<ExtensionType>
    {
        private readonly ushort code;

        private ExtensionType(ushort code)
        {
            this.code = code;
        }

        public static ExtensionType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new ExtensionType(code);
        }

        public void WriteBytes(Span<byte> bytes, out Span<byte> remainings)
        {
            NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            remainings = bytes.Slice(2);
        }

        public static ExtensionType ServerName { get; } = new ExtensionType(0);

        public static ExtensionType SupportedVersions { get; } = new ExtensionType(43);

        public static ExtensionType TransportParameters { get; } = new ExtensionType(65445);

        public bool Equals(ExtensionType other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is ExtensionType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(ExtensionType first, ExtensionType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ExtensionType first, ExtensionType second)
        {
            return !first.Equals(second);
        }
    }
}
