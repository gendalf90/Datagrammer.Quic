using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class UnknownExtension
    {
        public static ReadOnlyMemory<byte> SkipBytes(ReadOnlyMemory<byte> bytes)
        {
            ExtensionType.Parse(bytes, out bytes);
            ExtensionPayload.Slice(bytes, out bytes);

            return bytes;
        }
    }
}
