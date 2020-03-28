using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct PathFrame
    {
        public PathFrame(bool isChallenge,
                         bool isResponse,
                         ReadOnlyMemory<byte> data)
        {
            IsChallenge = isChallenge;
            IsResponse = isResponse;
            Data = data;
        }

        public bool IsChallenge { get; }

        public bool IsResponse { get; }

        public ReadOnlyMemory<byte> Data { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PathFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PathFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            var type = FrameType.Parse(bytes, out var afterTypeBytes);

            if (!type.IsPath())
            {
                return false;
            }

            var data = ParseData(afterTypeBytes, out var afterDataBytes);

            result = new PathFrame(type.IsChallenge(), type.IsResponse(), data);
            remainings = afterDataBytes;

            return true;
        }

        private static ReadOnlyMemory<byte> ParseData(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 8)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(8);

            return bytes.Slice(0, 8);
        }
    }
}
