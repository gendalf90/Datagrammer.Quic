using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CertificateVerify
    {
        private CertificateVerify(SignatureScheme scheme, MemoryBuffer signature)
        {
            Scheme = scheme;
            Signature = signature;
        }

        public SignatureScheme Scheme { get; }

        public MemoryBuffer Signature { get; }

        public static bool TryParse(MemoryCursor cursor, out CertificateVerify result)
        {
            result = new CertificateVerify();

            if(!HandshakeType.TrySlice(cursor, HandshakeType.CertificateVerify))
            {
                return false;
            }

            var body = HandshakeLength.SliceBytes(cursor);

            using var bodyContext = body.SetCursor(cursor);

            var scheme = SignatureScheme.Parse(cursor);
            var signature = ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

            if(cursor.HasNext())
            {
                throw new EncodingException();
            }

            result = new CertificateVerify(scheme, signature);

            return true;
        }

        public static CursorHandshakeWritingContext StartWriting(MemoryCursor cursor, SignatureScheme scheme)
        {
            HandshakeType.CertificateVerify.WriteBytes(cursor);

            var payloadContext = HandshakeLength.StartWriting(cursor);

            scheme.WriteBytes(cursor);

            var signatureContext = ByteVector.StartVectorWriting(cursor, 0..ushort.MaxValue);

            return new CursorHandshakeWritingContext(payloadContext, signatureContext);
        }
    }
}
