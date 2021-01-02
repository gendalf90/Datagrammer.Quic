using Datagrammer.Quic.Protocol.Error;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Datagrammer.Quic.Protocol.Tls.Certificates
{
    public class RsaCertificate : IPrivateCertificate, IPublicCertificate
    {
        private readonly HashAlgorithmName hashAlgorithm;
        private readonly RSASignaturePadding signaturePadding;
        private readonly X509Certificate2 certificate;

        private RsaCertificate(ReadOnlyMemory<byte> data, string password, HashAlgorithmName hashAlgorithm, RSASignaturePadding signaturePadding)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.signaturePadding = signaturePadding;

            certificate = new X509Certificate2(data.ToArray(), password);
        }

        private RsaCertificate(ReadOnlyMemory<byte> data, HashAlgorithmName hashAlgorithm, RSASignaturePadding signaturePadding)
        {
            this.hashAlgorithm = hashAlgorithm;
            this.signaturePadding = signaturePadding;

            certificate = new X509Certificate2(data.ToArray());
        }

        public void SignHash(ValueBuffer hash, MemoryCursor cursor)
        {
            var privateKey = certificate.GetRSAPrivateKey();

            if(privateKey == null)
            {
                throw new EncryptionException();
            }

            Span<byte> hashBuffer = stackalloc byte[hash.Length];

            hash.CopyTo(hashBuffer);

            var destination = cursor.PeekEnd();

            if(!privateKey.TrySignHash(hashBuffer, destination.Span, hashAlgorithm, signaturePadding, out var written))
            {
                throw new EncryptionException();
            }

            cursor.Move(written);
        }

        public bool VerifyHash(ValueBuffer hash, ReadOnlySpan<byte> signature)
        {
            var publicKey = certificate.GetRSAPublicKey();

            if (publicKey == null)
            {
                throw new EncryptionException();
            }

            Span<byte> hashBuffer = stackalloc byte[hash.Length];

            hash.CopyTo(hashBuffer);

            return publicKey.VerifyHash(hashBuffer, signature, hashAlgorithm, signaturePadding);
        }

        public void WritePublic(MemoryCursor cursor)
        {
            certificate.RawData.CopyTo(cursor);
        }

        public void Dispose()
        {
            certificate.Dispose();
        }

        public static RsaCertificate CreatePrivatePfx(ReadOnlyMemory<byte> data, string password, HashAlgorithmName hashAlgorithm, RSASignaturePadding signaturePadding)
        {
            return new RsaCertificate(data, password, hashAlgorithm, signaturePadding);
        }

        public static RsaCertificate CreatePublic(ReadOnlyMemory<byte> data, HashAlgorithmName hashAlgorithm, RSASignaturePadding signaturePadding)
        {
            return new RsaCertificate(data, hashAlgorithm, signaturePadding);
        }
    }
}
