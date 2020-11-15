using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct HandshakeWritingContext
    {
        private readonly HandshakeLength.WritingContext payloadContext;
        private readonly ByteVector.WritingContext vectorContext;

        public HandshakeWritingContext(
            HandshakeLength.WritingContext payloadContext,
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

    public readonly ref struct CursorHandshakeWritingContext
    {
        private readonly HandshakeLength.CursorWritingContext payloadContext;
        private readonly ByteVector.CursorWritingContext vectorContext;

        public CursorHandshakeWritingContext(
            HandshakeLength.CursorWritingContext payloadContext,
            ByteVector.CursorWritingContext vectorContext)
        {
            this.payloadContext = payloadContext;
            this.vectorContext = vectorContext;
        }

        public void Dispose()
        {
            vectorContext.Dispose();
            payloadContext.Dispose();
        }
    }
}
