﻿using System;

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

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if(type != ExtensionType.TransportParameters)
            {
                return false;
            }

            var payload = ExtensionPayload.Slice(afterTypeBytes, out remainings);

            result = new TransportParametersExtension(payload);

            return true;
        }

        public static ExtensionPayload.WritingContext StartWriting(Span<byte> destination)
        {
            ExtensionType.TransportParameters.WriteBytes(destination, out var remainings);

            return ExtensionPayload.StartWriting(remainings);
        }

        public override string ToString()
        {
            return BitConverter.ToString(Data.ToArray());
        }
    }
}
