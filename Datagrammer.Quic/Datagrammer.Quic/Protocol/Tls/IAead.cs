using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IAead : IDisposable
    {
        EncryptingContext StartEncrypting(ReadOnlySpan<byte> dataToEncrypt, MemoryCursor cursor);

        void Encrypt(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> dataToEncrypt, int sequenceNumber, Span<byte> destination);

        EncryptingContext StartDecrypting(ReadOnlySpan<byte> dataToDecrypt, MemoryCursor cursor);

        void Decrypt(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> dataToDecrypt, int sequenceNumber, Span<byte> destination);
    }
}
