using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ApplicationType : IEquatable<ApplicationType>
    {
        private readonly byte code;

        private ApplicationType(byte code)
        {
            this.code = code;
        }

        public static ApplicationType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var code = bytes.Span[0];

            remainings = bytes.Slice(1);

            return new ApplicationType(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            bytes[0] = code;
            bytes = bytes.Slice(1);
        }

        public static ApplicationType ApplicationData { get; } = new ApplicationType(0x17);

        public bool Equals(ApplicationType other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is ApplicationType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(ApplicationType first, ApplicationType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ApplicationType first, ApplicationType second)
        {
            return !first.Equals(second);
        }
    }
}
