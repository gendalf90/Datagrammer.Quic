using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Certificate
    {
        private Certificate(ReadOnlyMemory<byte> payload)
        {
            Payload = payload;
        }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out Certificate result, out ReadOnlyMemory<byte> remainings)
        {
            result = new Certificate();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = HandshakeType.Parse(bytes, out var afterTypeBytes);

            if (type != HandshakeType.Certificate)
            {
                return false;
            }

            var body = HandshakeLength.SliceHandshakeBytes(afterTypeBytes, out var afterBodyBytes);

            CertificateContext.SkipBytes(body, out var afterContextBytes);

            var payloadBytes = ByteVector.SliceVectorBytes(afterContextBytes, 0..ByteVector.MaxUInt24, out var afterPayloadBytes);

            if (!afterPayloadBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            result = new Certificate(payloadBytes);
            remainings = afterBodyBytes;

            return true;
        }

        public static HandshakeWritingContext StartWriting(ref Span<byte> destination)
        {
            HandshakeType.Certificate.WriteBytes(ref destination);

            var payloadContext = HandshakeLength.StartWriting(ref destination);

            CertificateContext.WriteEmpty(ref destination);

            var certificatesContext = ByteVector.StartVectorWriting(ref destination, 0..ByteVector.MaxUInt24);

            return new HandshakeWritingContext(payloadContext, certificatesContext);
        }

        public static CursorHandshakeWritingContext StartWriting(MemoryCursor cursor)
        {
            HandshakeType.Certificate.WriteBytes(cursor);

            var payloadContext = HandshakeLength.StartWriting(cursor);

            CertificateContext.WriteEmpty(cursor);

            var certificatesContext = ByteVector.StartVectorWriting(cursor, 0..ByteVector.MaxUInt24);

            return new CursorHandshakeWritingContext(payloadContext, certificatesContext);
        }
    }
}
