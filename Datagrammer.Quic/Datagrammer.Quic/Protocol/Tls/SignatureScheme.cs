using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls.Certificates;
using Datagrammer.Quic.Protocol.Tls.Hashes;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct SignatureScheme : IEquatable<SignatureScheme>
    {
        private static Dictionary<ushort, IHash> hashes = new Dictionary<ushort, IHash>
        {
            [0x0401] = Hash.Sha256
        };

        private static Dictionary<ushort, Func<ReadOnlyMemory<byte>, string, IPrivateCertificate>> privateCertificatePfxFactories = new Dictionary<ushort, Func<ReadOnlyMemory<byte>, string, IPrivateCertificate>>
        {
            [0x0401] = (data, password) => RsaCertificate.CreatePrivatePfx(data, password, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        };

        private static Dictionary<ushort, Func<ReadOnlyMemory<byte>, IPublicCertificate>> publicCertificateFactories = new Dictionary<ushort, Func<ReadOnlyMemory<byte>, IPublicCertificate>>
        {
            [0x0401] = (data) => RsaCertificate.CreatePublic(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        };

        private readonly ushort code;

        private SignatureScheme(ushort code)
        {
            this.code = code;
        }

        public static SignatureScheme Parse(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(bytes.Span);

            return new SignatureScheme(code);
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

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2).Span;

            NetworkBitConverter.WriteUnaligned(bytes, code, 2);
        }

        public static SignatureScheme RSA_PSS_RSAE_SHA256 { get; } = new SignatureScheme(0x0804);

        public static SignatureScheme RSA_PKCS1_SHA256 { get; } = new SignatureScheme(0x0401);

        public static SignatureScheme ECDSA_SECP256R1_SHA256 { get; } = new SignatureScheme(0x0403);

        public static SignatureScheme ECDSA_SECP384R1_SHA384 { get; } = new SignatureScheme(0x0503);

        public static SignatureScheme RSA_PSS_RSAE_SHA384 { get; } = new SignatureScheme(0x0805);

        public static SignatureScheme RSA_PKCS1_SHA386 { get; } = new SignatureScheme(0x0501);

        public static SignatureScheme RSA_PSS_RSAE_SHA512 { get; } = new SignatureScheme(0x0806);

        public static SignatureScheme RSA_PKCS1_SHA512 { get; } = new SignatureScheme(0x0601);

        public static SignatureScheme RSA_PKCS1_SHA1 { get; } = new SignatureScheme(0x0201);

        public static IEnumerable<SignatureScheme> Supported { get; } = new HashSet<SignatureScheme> { RSA_PKCS1_SHA256 };

        public IHash GetHash()
        {
            if (hashes.TryGetValue(code, out var hash))
            {
                return hash;
            }

            throw new NotSupportedException();
        }

        public IPrivateCertificate CreatePrivateCertificatePfx(ReadOnlyMemory<byte> data, string password)
        {
            if (privateCertificatePfxFactories.TryGetValue(code, out var factory))
            {
                return factory(data, password);
            }

            throw new NotSupportedException();
        }

        public IPublicCertificate CreatePublicCertificate(ReadOnlyMemory<byte> data)
        {
            if (publicCertificateFactories.TryGetValue(code, out var factory))
            {
                return factory(data);
            }

            throw new NotSupportedException();
        }

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
