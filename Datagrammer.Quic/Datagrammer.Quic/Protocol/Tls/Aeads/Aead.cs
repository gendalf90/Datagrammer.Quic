using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Aeads
{
    public abstract class Aead : IAead
    {
        public abstract int TagLength { get; }

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

        public virtual void Dispose()
        {
        }

        public abstract void Encrypt(Span<byte> data, Span<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData);

        public abstract void Decrypt(Span<byte> data, ReadOnlySpan<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData);
    }
}
