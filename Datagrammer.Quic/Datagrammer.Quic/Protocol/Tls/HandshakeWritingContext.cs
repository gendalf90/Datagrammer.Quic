using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public ref struct HandshakeWritingContext
    {
        private HandshakeLength.WritingContext payloadContext;
        private ByteVector.WritingContext vectorContext;

        public HandshakeWritingContext(HandshakeLength.WritingContext payloadContext,
                                       ByteVector.WritingContext vectorContext)
        {
            this.payloadContext = payloadContext;
            this.vectorContext = vectorContext;

            Cursor = vectorContext.Cursor;
        }

        public WritingCursor Cursor { get; set; }

        public void Complete(out Span<byte> remainings)
        {
            payloadContext.Cursor = payloadContext.Cursor.Move(vectorContext.Complete());

            payloadContext.Complete();

            remainings = payloadContext.Cursor.Destination;
        }
    }
}
