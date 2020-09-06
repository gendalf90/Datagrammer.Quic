using Datagrammer.Quic.Protocol.Error;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using CurveX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct NamedGroup : IEquatable<NamedGroup>
    {
        private static Dictionary<ushort, Func<byte[]>> privateKeyGenerators = new Dictionary<ushort, Func<byte[]>>
        {
            [0x001D] = GenerateX25519PrivateKey
        };

        private static Dictionary<ushort, Func<byte[], byte[]>> publicKeyGenerators = new Dictionary<ushort, Func<byte[], byte[]>>
        {
            [0x001D] = GenerateX25519PublicKey
        };

        private readonly ushort code;

        private NamedGroup(ushort code)
        {
            this.code = code;
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

        public void WriteBytes(Stream stream)
        {
            NetworkBitConverter.WriteUnaligned(stream, code, 2);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            bytes = bytes.Slice(NetworkBitConverter.WriteUnaligned(bytes, code, 2));
        }

        public static NamedGroup X25519 { get; } = new NamedGroup(0x001D);

        public static NamedGroup SECP256R1 { get; } = new NamedGroup(0x0017);

        public static NamedGroup SECP384R1 { get; } = new NamedGroup(0x0018);

        public static IEnumerable<NamedGroup> Supported { get; } = new HashSet<NamedGroup> { X25519 };

        public ReadOnlyMemory<byte> GeneratePrivateKey()
        {
            if (privateKeyGenerators.TryGetValue(code, out var generator))
            {
                return generator();
            }

            throw new NotSupportedException();
        }

        public ReadOnlyMemory<byte> GeneratePublicKey(ReadOnlyMemory<byte> privateKey)
        {
            if (publicKeyGenerators.TryGetValue(code, out var generator))
            {
                return generator(privateKey.ToArray());
            }

            throw new NotSupportedException();
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
