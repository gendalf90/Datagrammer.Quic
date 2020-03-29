using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct Error
    {
        private Error(ulong code,
                      bool isTransport,
                      bool isApplication)
        {
            Code = code;
            IsTransport = isTransport;
            IsApplication = isApplication;
        }

        public ulong Code { get; }

        public bool IsTransport { get; }

        public bool IsApplication { get; }

        public static Error ParseApplication(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var code = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new Error(code, false, true);
        }

        public static Error ParseTransport(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var code = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new Error(code, true, false);
        }
    }
}
