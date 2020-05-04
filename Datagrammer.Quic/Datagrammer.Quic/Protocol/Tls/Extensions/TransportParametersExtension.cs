using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct TransportParametersExtension
    {
        private TransportParametersExtension(ReadOnlyMemory<byte> data)
        {
            Data = data;
        }

        public ReadOnlyMemory<byte> Data { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out TransportParametersExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new TransportParametersExtension();
            remainings = bytes;

            if(bytes.IsEmpty)
            {
                return false;
            }

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if(type != ExtensionType.TransportParameters)
            {
                return false;
            }

            var payload = ExtensionLength.SlicePayload(afterTypeBytes, out remainings);

            result = new TransportParametersExtension(payload);

            return true;
        }
    }
}
