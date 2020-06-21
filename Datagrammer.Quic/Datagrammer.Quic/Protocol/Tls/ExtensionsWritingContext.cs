using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct ExtensionsWritingContext
    {
        private readonly HandshakeLength.WritingContext payloadContext;
        private readonly ByteVector.WritingContext vectorContext;

        public ExtensionsWritingContext(HandshakeLength.WritingContext payloadContext,
                                       ByteVector.WritingContext vectorContext)
        {
            this.payloadContext = payloadContext;
            this.vectorContext = vectorContext;
        }

        public void Complete(ref Span<byte> bytes)
        {
            vectorContext.Complete(ref bytes);
            payloadContext.Complete(ref bytes);
        }
    }
}
