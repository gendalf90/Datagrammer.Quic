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

        protected override int GetTagLength()
        {
            return Chacha20Poly1305.TagSize;
        }

        protected override void Encrypt(CryptoToken token)
        {
            Span<byte> nonce = stackalloc byte[Chacha20Poly1305.NonceSize];

            BuildNonce(iv, token.SequenceNumber, nonce);

            var destinationData = token.Result.Slice(0, token.Source.Length);
            var destinationTag = token.Result.Slice(token.Source.Length, Chacha20Poly1305.TagSize);

            algorithm.Encrypt(nonce, token.Source, destinationData, destinationTag, token.AssociatedData);
        }

        protected override void Decrypt(CryptoToken token)
        {
            Span<byte> nonce = stackalloc byte[Chacha20Poly1305.NonceSize];

            BuildNonce(iv, token.SequenceNumber, nonce);

            var sourceTag = token.Source.Slice(token.Source.Length - Chacha20Poly1305.TagSize);
            var sourceData = token.Source.Slice(0, token.Source.Length - Chacha20Poly1305.TagSize);

            algorithm.Decrypt(nonce, sourceData, sourceTag, token.Result, token.AssociatedData);
        }

        public override void Dispose()
        {
            algorithm.Dispose();
        }
    }
}
