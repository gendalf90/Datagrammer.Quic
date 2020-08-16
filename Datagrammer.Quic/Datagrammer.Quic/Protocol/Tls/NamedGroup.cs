using Datagrammer.Quic.Protocol.Error;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using CurveX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace Datagrammer.Quic.Protocol.Tls
{
    public class NamedGroup : IEquatable<NamedGroup>
    {
        private readonly ushort code;
        private readonly Func<byte[]> privateKeyStrategy;
        private readonly Func<byte[], byte[]> publicKeyStrategy;

        private NamedGroup(
            ushort code, 
            Func<byte[]> privateKeyStrategy,
            Func<byte[], byte[]> publicKeyStrategy)
        {
            this.code = code;
            this.privateKeyStrategy = privateKeyStrategy;
            this.publicKeyStrategy = publicKeyStrategy;
        }

        public bool TrySliceBytes(ref ReadOnlyMemory<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            if(this.code != code)
            {
                return false;
            }

            bytes = bytes.Slice(2);

            return true;
        }

        public static void SliceBytes(ref ReadOnlyMemory<byte> bytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            bytes = bytes.Slice(2);
        }

        public void WriteBytes(Stream stream)
        {
            NetworkBitConverter.WriteUnaligned(stream, code, 2);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            bytes = bytes.Slice(NetworkBitConverter.WriteUnaligned(bytes, code, 2));
        }

        public static NamedGroup X25519 { get; } = new NamedGroup(0x001D, GenerateX25519PrivateKey, GenerateX25519PublicKey);

        public static NamedGroup SECP256R1 { get; } = new NamedGroup(0x0017, () => throw new NotImplementedException(), _ => throw new NotImplementedException());

        public static NamedGroup SECP384R1 { get; } = new NamedGroup(0x0018, () => throw new NotImplementedException(), _ => throw new NotImplementedException());

        public ReadOnlyMemory<byte> GeneratePrivateKey()
        {
            return privateKeyStrategy();
        }

        public ReadOnlyMemory<byte> GeneratePublicKey(ReadOnlyMemory<byte> privateKey)
        {
            return publicKeyStrategy(privateKey.ToArray());
        }

        private static byte[] GenerateX25519PrivateKey()
        {
            var buffer = new byte[CurveX25519.ScalarSize];

            CurveX25519.GeneratePrivateKey(new SecureRandom(), buffer);

            return buffer;
        }

        private static byte[] GenerateX25519PublicKey(byte[] privateKey)
        {
            var buffer = new byte[CurveX25519.ScalarSize];

            CurveX25519.GeneratePublicKey(privateKey, 0, buffer, 0);

            return buffer;
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
