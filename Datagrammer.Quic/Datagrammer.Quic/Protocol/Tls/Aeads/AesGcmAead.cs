using Datagrammer.Quic.Protocol.Error;
using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public class AesGcmAead : IAead
    {
        private const int TagLength = 16;
        private const int NonceLength = 12;

        private readonly ReadOnlyMemory<byte> key;
        private readonly ReadOnlyMemory<byte> iv;
        private readonly AesGcm algorithm;

        public AesGcmAead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            this.iv = iv;
            this.key = key;

            algorithm = new AesGcm(key.Span);
        }

        private void BuildNonce(ReadOnlyMemory<byte> iv, long sequenceNumber, Span<byte> result)
        {
            if (!iv.Span.TryCopyTo(result))
            {
                throw new EncryptionException();
            }

            for (int i = 0; i < 8; i++)
            {
                result[iv.Length - 1 - i] = (byte)(iv.Span[iv.Length - 1 - i] ^ ((sequenceNumber >> (i * 8)) & 0xFF));
            }
        }

        public CryptingToken StartEncrypting(ReadOnlySpan<byte> data, MemoryCursor cursor)
        {
            var resultBuffer = cursor.Move(data.Length + TagLength);

            return new CryptingToken(true, data, resultBuffer.Span);
        }

        public CryptingToken StartDecrypting(ReadOnlySpan<byte> data, MemoryCursor cursor)
        {
            if (data.Length < TagLength)
            {
                throw new EncryptionException();
            }

            var resultBuffer = cursor.Move(data.Length - TagLength);

            return new CryptingToken(false, data, resultBuffer.Span);
        }

        public void Finish(CryptingToken token)
        {
            try
            {
                if(token.IsEncrypting)
                {
                    Encrypt(token);
                }
                
                if(token.IsDecrypting)
                {
                    Decrypt(token);
                }
            }
            catch (Exception e)
            {
                throw new EncryptionException("", e);
            }
        }

        private void Encrypt(CryptingToken token)
        {
            Span<byte> nonce = stackalloc byte[NonceLength];

            BuildNonce(iv, token.SequenceNumber, nonce);

            var destinationData = token.Result.Slice(0, token.Source.Length);
            var destinationTag = token.Result.Slice(token.Source.Length, TagLength);

            algorithm.Encrypt(nonce, token.Source, destinationData, destinationTag, token.AssociatedData);
        }

        private void Decrypt(CryptingToken token)
        {
            Span<byte> nonce = stackalloc byte[NonceLength];

            BuildNonce(iv, token.SequenceNumber, nonce);

            var tag = token.Source.Slice(token.Source.Length - TagLength);
            var data = token.Source.Slice(0, token.Source.Length - TagLength);

            algorithm.Decrypt(nonce, data, tag, token.Result, token.AssociatedData);
        }

        public void Dispose()
        {
            algorithm.Dispose();
        }
    }
}
