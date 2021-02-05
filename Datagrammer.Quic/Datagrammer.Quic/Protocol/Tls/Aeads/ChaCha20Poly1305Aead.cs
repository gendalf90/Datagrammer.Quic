using AtlasRhythm.Cryptography.Aeads;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public sealed class ChaCha20Poly1305Aead : Aead
    {
        private readonly ReadOnlyMemory<byte> iv;
        private readonly Chacha20Poly1305 algorithm;

        public ChaCha20Poly1305Aead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            this.iv = iv;

            algorithm = new Chacha20Poly1305(key.ToArray());
        }

        public override int TagLength => Chacha20Poly1305.TagSize;

        public override void Encrypt(Span<byte> data, Span<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData)
        {
            Span<byte> nonce = stackalloc byte[Chacha20Poly1305.NonceSize];

            BuildNonce(iv, sequenceNumber, nonce);

            algorithm.Encrypt(nonce, data, data, tag, associatedData);
        }

        public override void Decrypt(Span<byte> data, ReadOnlySpan<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData)
        {
            Span<byte> nonce = stackalloc byte[Chacha20Poly1305.NonceSize];

            BuildNonce(iv, sequenceNumber, nonce);

            algorithm.Decrypt(nonce, data, tag, data, associatedData);
        }

        public override void Dispose()
        {
            algorithm.Dispose();
        }
    }
}
