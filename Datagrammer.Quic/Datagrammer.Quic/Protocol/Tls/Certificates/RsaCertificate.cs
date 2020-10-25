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

        public void SignHash(ReadOnlyMemory<byte> hash, ref Span<byte> destination)
        {
            var privateKey = certificate.GetRSAPrivateKey();

            if(privateKey == null)
            {
                throw new EncryptionException();
            }

            if(!privateKey.TrySignHash(hash.Span, destination, hashAlgorithm, signaturePadding, out var written))
            {
                throw new EncryptionException();
            }

            destination = destination.Slice(written);
        }

        public bool VerifyHash(ReadOnlyMemory<byte> hash, ReadOnlyMemory<byte> signature)
        {
            var publicKey = certificate.GetRSAPublicKey();

            if (publicKey == null)
            {
                throw new EncryptionException();
            }

            return publicKey.VerifyHash(hash.Span, signature.Span, hashAlgorithm, signaturePadding);
        }

        public void WritePublic(ref Span<byte> destination)
        {
            var raw = certificate.RawData.AsSpan();

            if (!raw.TryCopyTo(destination))
            {
                throw new EncryptionException();
            }

            destination = destination.Slice(raw.Length);
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
