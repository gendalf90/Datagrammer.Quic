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

        public void Encrypt(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> dataToEncrypt, int sequenceNumber, Span<byte> destination)
        {
            try
            {
                Span<byte> nonce = stackalloc byte[NonceLength];

                BuildNonce(iv, sequenceNumber, nonce);

                var destinationData = destination.Slice(0, dataToEncrypt.Length);
                var destinationTag = destination.Slice(dataToEncrypt.Length, TagLength);

                algorithm.Encrypt(nonce, dataToEncrypt, destinationData, destinationTag, associatedData);
            }
            catch (Exception e)
            {
                throw new EncryptionException("", e);
            }
        }

        public void Decrypt(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> dataToDecrypt, int sequenceNumber, Span<byte> destination)
        {
            try
            {
                Span<byte> nonce = stackalloc byte[NonceLength];

                BuildNonce(iv, sequenceNumber, nonce);

                var tag = dataToDecrypt.Slice(dataToDecrypt.Length - TagLength, TagLength);
                var data = dataToDecrypt.Slice(0, dataToDecrypt.Length - tag.Length);
                var destinationData = destination.Slice(0, data.Length);

                algorithm.Decrypt(nonce, data, tag, destinationData, associatedData);
            }
            catch (Exception e)
            {
                throw new EncryptionException("", e);
            }
        }

        public void Dispose()
        {
            algorithm.Dispose();
        }

        public EncryptingContext StartEncrypting(ReadOnlySpan<byte> dataToEncrypt, MemoryCursor cursor)
        {
            var buffer = cursor.Move(dataToEncrypt.Length + TagLength);

            return new EncryptingContext(true, this, dataToEncrypt, buffer.Span);
        }

        public EncryptingContext StartDecrypting(ReadOnlySpan<byte> dataToDecrypt, MemoryCursor cursor)
        {
            if(dataToDecrypt.Length < TagLength)
            {
                throw new EncryptionException();
            }

            var buffer = cursor.Move(dataToDecrypt.Length - TagLength);

            return new EncryptingContext(false, this, dataToDecrypt, buffer.Span);
        }
    }
}
