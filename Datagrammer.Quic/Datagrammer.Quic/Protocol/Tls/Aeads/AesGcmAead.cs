using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public sealed class AesGcmAead : Aead
    {
        private readonly ReadOnlyMemory<byte> iv;
        private readonly AesGcm algorithm;

        public AesGcmAead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            this.iv = iv;
            
            algorithm = new AesGcm(key.Span);
        }

        public override int TagLength => 16;

        public override void Encrypt(Span<byte> data, Span<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData)
        {
            Span<byte> nonce = stackalloc byte[12];

            BuildNonce(iv, sequenceNumber, nonce);

            algorithm.Encrypt(nonce, data, data, tag, associatedData);
        }

        public override void Decrypt(Span<byte> data, ReadOnlySpan<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData)
        {
            Span<byte> nonce = stackalloc byte[12];

            BuildNonce(iv, sequenceNumber, nonce);

            algorithm.Decrypt(nonce, data, tag, data, associatedData);
        }

        public override void Dispose()
        {
            algorithm.Dispose();
        }
    }
}
