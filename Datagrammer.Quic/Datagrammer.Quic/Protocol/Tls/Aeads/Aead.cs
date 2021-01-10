using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public abstract class Aead : IAead
    {
        protected abstract int GetTagLength();

        protected void BuildNonce(ReadOnlyMemory<byte> iv, ulong sequenceNumber, Span<byte> result)
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

        public CryptoToken StartEncryption(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            var tagLength = GetTagLength();
            var resultLength = data.Length + tagLength;

            if (destination.Length < resultLength)
            {
                throw new EncryptionException();
            }

            return new CryptoToken(true, data, destination.Slice(0, resultLength));
        }

        public CryptoToken StartDecryption(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            var tagLength = GetTagLength();

            if (data.Length < tagLength)
            {
                throw new EncryptionException();
            }

            var resultLength = data.Length - tagLength;

            if (destination.Length < resultLength)
            {
                throw new EncryptionException();
            }

            return new CryptoToken(false, data, destination.Slice(0, resultLength));
        }

        public void Finish(CryptoToken token)
        {
            try
            {
                if (token.IsEncrypt)
                {
                    Encrypt(token);
                }

                if (token.IsDecrypt)
                {
                    Decrypt(token);
                }
            }
            catch (Exception e)
            {
                throw new EncryptionException("", e);
            }
        }

        protected abstract void Encrypt(CryptoToken token);

        protected abstract void Decrypt(CryptoToken token);

        public abstract void Dispose();
    }
}
