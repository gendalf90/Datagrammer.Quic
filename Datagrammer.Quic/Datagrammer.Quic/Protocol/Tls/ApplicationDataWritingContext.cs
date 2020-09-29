using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly ref struct ApplicationDataWritingContext
    {
        private readonly ApplicationLength.WritingContext payloadContext;

        public ApplicationDataWritingContext(ApplicationLength.WritingContext payloadContext)
        {
            this.payloadContext = payloadContext;
        }

        public void Complete(ref Span<byte> bytes)
        {
            payloadContext.Complete(ref bytes);
        }
    }
}
