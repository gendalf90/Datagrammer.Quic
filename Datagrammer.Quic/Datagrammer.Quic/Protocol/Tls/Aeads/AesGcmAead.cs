using Datagrammer.Quic.Protocol.Error;
using System;
using System.Security.Cryptography;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public class AesGcmAead : IAead
    {
        private readonly ReadOnlyMemory<byte> key;
        private readonly ReadOnlyMemory<byte> iv;
        private readonly AesGcm algorithm;

        public AesGcmAead(ReadOnlyMemory<byte> iv, ReadOnlyMemory<byte> key)
        {
            this.iv = iv;
            this.key = key;

            algorithm = new AesGcm(key.Span);
        }

        private void BuildNonce(ReadOnlyMemory<byte> iv, long seq, Span<byte> result)
        {
            if (!iv.Span.TryCopyTo(result))
            {
                throw new EncryptionException();
            }

            for (int i = 0; i < 8; i++)
            {
                result[iv.Length - 1 - i] = (byte)(iv.Span[iv.Length - 1 - i] ^ ((seq >> (i * 8)) & 0xFF));
            }
        }

        public void Encrypt(ReadOnlySpan<byte> dataToEncrypt, int seq, ref Span<byte> destination)
        {
            try
            {
                Span<byte> nonce = stackalloc byte[iv.Length];

                BuildNonce(iv, seq, nonce);

                var header = dataToEncrypt.Slice(0, 5);
                var data = dataToEncrypt.Slice(5);
                var destinationData = destination.Slice(5, data.Length);
                var destinationTag = destination.Slice(dataToEncrypt.Length, key.Length);

                header.CopyTo(destination);
                algorithm.Encrypt(nonce, data, destinationData, destinationTag, header);

                destination = destination.Slice(dataToEncrypt.Length + key.Length);
            }
            catch (Exception e)
            {
                throw new EncryptionException("", e);
            }
        }

        public void Decrypt(ReadOnlySpan<byte> dataToDecrypt, int seq, ref Span<byte> destination)
        {
            try
            {
                Span<byte> nonce = stackalloc byte[iv.Length];

                BuildNonce(iv, seq, nonce);

                var header = dataToDecrypt.Slice(0, 5);
                var tag = dataToDecrypt.Slice(dataToDecrypt.Length - key.Length, key.Length);
                var data = dataToDecrypt.Slice(5, dataToDecrypt.Length - key.Length - 5);
                var destinationData = destination.Slice(5, data.Length);

                header.CopyTo(destination);
                algorithm.Decrypt(nonce, data, tag, destinationData, header);

                destination = destination.Slice(header.Length + data.Length);
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
    }
}
