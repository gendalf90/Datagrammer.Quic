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

        public void WriteBytes(ref Span<byte> bytes)
        {
            var writtenLength = NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            bytes = bytes.Slice(writtenLength);
        }

        public static Cipher TLS_AES_128_GCM_SHA256 { get; } = new Cipher(0x1301);

        public static Cipher TLS_AES_256_GCM_SHA384 { get; } = new Cipher(0x1302);

        public static Cipher TLS_CHACHA20_POLY1305_SHA256 { get; } = new Cipher(0x1303);

        public bool Equals(Cipher other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is Cipher version && Equals(version);
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
