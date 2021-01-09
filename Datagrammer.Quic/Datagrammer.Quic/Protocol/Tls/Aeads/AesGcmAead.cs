﻿using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public sealed class AesGcmAead : Aead
    {
        private const int TagLength = 16;
        private const int NonceLength = 12;

        private readonly ReadOnlyMemory<byte> iv;
        private readonly AesGcm algorithm;

        public AesGcmAead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            this.iv = iv;

            algorithm = new AesGcm(key.Span);
        }

        protected override int GetTagLength()
        {
            return TagLength;
        }

        protected override void Encrypt(CryptoToken token, ReadOnlySpan<byte> associatedData, int sequenceNumber)
        {
            Span<byte> nonce = stackalloc byte[NonceLength];

            BuildNonce(iv, sequenceNumber, nonce);

            var destinationData = token.Result.Slice(0, token.Source.Length);
            var destinationTag = token.Result.Slice(token.Source.Length, TagLength);

            algorithm.Encrypt(nonce, token.Source, destinationData, destinationTag, associatedData);
        }

        protected override void Decrypt(CryptoToken token, ReadOnlySpan<byte> associatedData, int sequenceNumber)
        {
            Span<byte> nonce = stackalloc byte[NonceLength];

            BuildNonce(iv, sequenceNumber, nonce);

            var sourceTag = token.Source.Slice(token.Source.Length - TagLength);
            var sourceData = token.Source.Slice(0, token.Source.Length - TagLength);

            algorithm.Decrypt(nonce, sourceData, sourceTag, token.Result, associatedData);
        }

        public override void Dispose()
        {
            algorithm.Dispose();
        }
    }
}
