using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct CryptoToken
    {
        public CryptoToken(
             bool isEncrypt,
             ReadOnlySpan<byte> sourceBuffer,
             Span<byte> resultBuffer,
             ulong sequenceNumber = default,
             ReadOnlySpan<byte> associatedData = default)
        {
            IsEncrypt = isEncrypt;
            IsDecrypt = !isEncrypt;
            Source = sourceBuffer;
            Result = resultBuffer;
            SequenceNumber = sequenceNumber;
            AssociatedData = associatedData;
        }

        public ReadOnlySpan<byte> Source { get; }

        public Span<byte> Result { get; }

        public ulong SequenceNumber { get; }

        public ReadOnlySpan<byte> AssociatedData { get; }

        public bool IsEncrypt { get; }

        public bool IsDecrypt { get; }
    }

    public static class CryptoTokenExtensions
    {
        public static void UseSequenceNumber(this ref CryptoToken token, ulong sequenceNumber)
        {
            token = new CryptoToken(token.IsEncrypt, token.Source, token.Result, sequenceNumber, token.AssociatedData);
        }

        public static void UseAssociatedData(this ref CryptoToken token, ReadOnlySpan<byte> associatedData)
        {
            token = new CryptoToken(token.IsEncrypt, token.Source, token.Result, token.SequenceNumber, associatedData);
        }
    }
}
