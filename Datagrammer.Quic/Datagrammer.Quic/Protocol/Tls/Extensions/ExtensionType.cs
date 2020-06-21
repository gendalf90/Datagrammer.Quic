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

        public void WriteBytes(ref Span<byte> bytes)
        {
            var writtenLength = NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            bytes = bytes.Slice(writtenLength);
        }

        public static ExtensionType SupportedVersions { get; } = new ExtensionType(43); //0x2b

        public static ExtensionType SignatureAlgorithms { get; } = new ExtensionType(13);

        public static ExtensionType ApplicationLayerProtocolNegotiation { get; } = new ExtensionType(16);

        public static ExtensionType SupportedGroups { get; } = new ExtensionType(10);

        public static ExtensionType PskKeyExchangeModes { get; } = new ExtensionType(45);

        public static ExtensionType KeyShare { get; } = new ExtensionType(51); //0x33

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
