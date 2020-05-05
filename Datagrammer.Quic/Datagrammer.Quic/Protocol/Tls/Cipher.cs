using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Cipher : IEquatable<Cipher>
    {
        private readonly ushort code;

        private Cipher(ushort code)
        {
            this.code = code;
        }

        public static Cipher Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new Cipher(code);
        }

        public int WriteBytes(Span<byte> bytes)
        {
            return NetworkBitConverter.WriteUnaligned(bytes, code, 2);
        }

        public static Cipher TLS_AES_128_GCM_SHA256 { get; } = new Cipher(4865);

        public bool Equals(Cipher other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is ProtocolVersion version && Equals(version);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(Cipher first, Cipher second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(Cipher first, Cipher second)
        {
            return !first.Equals(second);
        }
    }
}
