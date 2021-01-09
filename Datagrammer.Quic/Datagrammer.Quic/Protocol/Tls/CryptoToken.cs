using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct CryptoToken
    {
        private readonly bool isEncrypt;
        private readonly ReadOnlySpan<byte> sourceBuffer;
        private readonly Span<byte> resultBuffer;

        public CryptoToken(
             bool isEncrypt,
             ReadOnlySpan<byte> sourceBuffer,
             Span<byte> resultBuffer)
        {
            this.isEncrypt = isEncrypt;
            this.sourceBuffer = sourceBuffer;
            this.resultBuffer = resultBuffer;
        }

        public ReadOnlySpan<byte> Source => sourceBuffer;

        public Span<byte> Result => resultBuffer;

        public bool IsEncrypt => isEncrypt;

        public bool IsDecrypt => !isEncrypt;
    }
}
