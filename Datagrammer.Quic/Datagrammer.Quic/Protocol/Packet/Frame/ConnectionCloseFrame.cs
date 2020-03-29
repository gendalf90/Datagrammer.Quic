using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct ConnectionCloseFrame
    {
        private ConnectionCloseFrame(Error error,
                                     FrameType? errorFrameType,
                                     ReasonPhrase reasonPhrase)
        {
            Error = error;
            ErrorFrameType = errorFrameType;
            ReasonPhrase = reasonPhrase;
        }

        public Error Error { get; }

        public FrameType? ErrorFrameType { get; }

        public ReasonPhrase ReasonPhrase { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ConnectionCloseFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new ConnectionCloseFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsConnectionClose())
            {
                return false;
            }

            var error = new Error();
            var afterErrorBytes = afterTypeBytes;

            if(type.HasApplicationError())
            {
                error = Error.ParseApplication(afterTypeBytes, out afterErrorBytes);
            }

            if(type.HasTransportError())
            {
                error = Error.ParseTransport(afterTypeBytes, out afterErrorBytes);
            }

            var afterErrorFrameTypeBytes = afterErrorBytes;
            var errorFrameType = type.HasTransportError() ? FrameType.Parse(afterErrorBytes, out afterErrorFrameTypeBytes) : new FrameType?();
            var reasonPhrase = ReasonPhrase.Parse(afterErrorFrameTypeBytes, out var afterReasonPhraseBytes);

            result = new ConnectionCloseFrame(error, errorFrameType, reasonPhrase);
            remainings = afterReasonPhraseBytes;

            return true;
        }
    }
}
