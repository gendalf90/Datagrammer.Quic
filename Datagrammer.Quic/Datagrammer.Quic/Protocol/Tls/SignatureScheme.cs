using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct SignatureScheme : IEquatable<SignatureScheme>
    {
        private readonly ushort code;

        private SignatureScheme(ushort code)
        {
            this.code = code;
        }

        public static SignatureScheme Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new SignatureScheme(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            bytes = bytes.Slice(NetworkBitConverter.WriteUnaligned(bytes, code, 2));
        }

        public static SignatureScheme RSA_PSS_RSAE_SHA256 { get; } = new SignatureScheme(0x0804);

        public static SignatureScheme RSA_PKCS1_SHA256 { get; } = new SignatureScheme(0x0401);

        public static SignatureScheme ECDSA_SECP256R1_SHA256 { get; } = new SignatureScheme(0x0403);

        public bool Equals(SignatureScheme other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is SignatureScheme version && Equals(version);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(SignatureScheme first, SignatureScheme second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(SignatureScheme first, SignatureScheme second)
        {
            return !first.Equals(second);
        }
    }
}
