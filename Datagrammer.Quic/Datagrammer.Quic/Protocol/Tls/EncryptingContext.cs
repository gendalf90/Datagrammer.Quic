using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct EncryptingContext
    {
        private readonly bool isEncrypting;
        private readonly IAead aead;
        private readonly ReadOnlySpan<byte> sourceBuffer;
        private readonly Span<byte> resultBuffer;

        public EncryptingContext(
            bool isEncrypting,
            IAead aead,
            ReadOnlySpan<byte> sourceBuffer,
            Span<byte> resultBuffer)
        {
            this.isEncrypting = isEncrypting;
            this.aead = aead;
            this.sourceBuffer = sourceBuffer;
            this.resultBuffer = resultBuffer;
        }

        public ReadOnlySpan<byte> ResultBuffer => resultBuffer;

        public void Complete(ReadOnlySpan<byte> associatedData, int sequenceNumber)
        {
            if (isEncrypting)
            {
                aead.Encrypt(associatedData, sourceBuffer, sequenceNumber, resultBuffer);
            }
            else
            {
                aead.Decrypt(associatedData, sourceBuffer, sequenceNumber, resultBuffer);
            }
        }
    }
}
