using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CertificateVerify
    {
        private CertificateVerify(SignatureScheme scheme, ReadOnlyMemory<byte> signature)
        {
            Scheme = scheme;
            Signature = signature;
        }

        public SignatureScheme Scheme { get; }

        public ReadOnlyMemory<byte> Signature { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out CertificateVerify result, out ReadOnlyMemory<byte> remainings)
        {
            result = new CertificateVerify();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var type = HandshakeType.Parse(bytes, out var afterTypeBytes);

            if (type != HandshakeType.CertificateVerify)
            {
                return false;
            }

            var body = HandshakeLength.SliceHandshakeBytes(afterTypeBytes, out var afterBodyBytes);
            var scheme = SignatureScheme.Parse(body, out var afterSchemeBytes);
            var signature = ByteVector.SliceVectorBytes(afterSchemeBytes, 0..ushort.MaxValue, out var afterSignatureBytes);

            if (!afterSignatureBytes.IsEmpty)
            {
                throw new EncodingException();
            }

            result = new CertificateVerify(scheme, signature);
            remainings = afterBodyBytes;

            return true;
        }

        public static HandshakeWritingContext StartWriting(ref Span<byte> destination, SignatureScheme scheme)
        {
            HandshakeType.CertificateVerify.WriteBytes(ref destination);

            var payloadContext = HandshakeLength.StartWriting(ref destination);

            scheme.WriteBytes(ref destination);

            var signatureContext = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            return new HandshakeWritingContext(payloadContext, signatureContext);
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
