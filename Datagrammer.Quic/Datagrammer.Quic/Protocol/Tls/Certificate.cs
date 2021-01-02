using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Certificate
    {
        private Certificate(MemoryBuffer payload)
        {
            Payload = payload;
        }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, out Certificate result)
        {
            result = new Certificate();

            if(!HandshakeType.TrySlice(cursor, HandshakeType.Certificate))
            {
                return false;
            }

            var body = HandshakeLength.SliceBytes(cursor);

            using var bodyContext = body.SetCursor(cursor);

            CertificateContext.SkipBytes(cursor);

            var payloadBytes = ByteVector.SliceVectorBytes(cursor, 0..ByteVector.MaxUInt24);

            if(!cursor.IsEnd())
            {
                throw new EncodingException();
            }

            result = new Certificate(payloadBytes);

            return true;
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
