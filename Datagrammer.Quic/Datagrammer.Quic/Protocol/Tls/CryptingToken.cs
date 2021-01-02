using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public ref struct CryptingToken
    {
        private readonly bool isEncrypting;
        private readonly ReadOnlySpan<byte> sourceBuffer;
        private readonly Span<byte> resultBuffer;

        internal CryptingToken(
             bool isEncrypting,
             ReadOnlySpan<byte> sourceBuffer,
             Span<byte> resultBuffer)
        {
            this.isEncrypting = isEncrypting;
            this.sourceBuffer = sourceBuffer;
            this.resultBuffer = resultBuffer;

            SequenceNumber = 0;
            AssociatedData = ReadOnlySpan<byte>.Empty;
        }

        public ReadOnlySpan<byte> Source => sourceBuffer;

        public Span<byte> Result => resultBuffer;

        public bool IsEncrypting => isEncrypting;

        public bool IsDecrypting => !isEncrypting;

        public int SequenceNumber { get; set; }

        public ReadOnlySpan<byte> AssociatedData { get; set; }
    }
}
