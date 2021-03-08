using Datagrammer.Quic.Protocol.Packet;
using Xunit;

namespace Tests.Packet
{
    public class PacketNumberTests
    {
        [Theory]
        [InlineData("9b32", "a82f30ea", "a82f9b32")]
        [InlineData("5c02", "abe8bc", "ac5c02")]
        [InlineData("ace8fe", "abe8bc", "ace8fe")]
        [InlineData("bff4", "2700bec8", "2700bff4")]
        public void Decode_ByLargestAcknowledged_ResultIsExpected(string truncated, string largest, string expected)
        {
            //Arrange
            var truncatedNumber = PacketNumber.Parse(Utils.ParseHexString(truncated));
            var largestNumber = PacketNumber.Parse(Utils.ParseHexString(largest));
            var expectedNumber = PacketNumber.Parse(Utils.ParseHexString(expected));

            //Act
            var resultNumber = truncatedNumber.DecodeByLargestAcknowledged(largestNumber);

            //Assert
            Assert.Equal(expectedNumber, resultNumber);
        }

        [Theory]
        [InlineData("a82f9b32", "a82f30ea", "9b32")]
        [InlineData("ac5c02", "abe8bc", "5c02")]
        [InlineData("ace8fe", "abe8bc", "ace8fe")]
        [InlineData("2700bff4", "2700bec8", "bff4")]
        public void Encode_ByLargestAcknowledged_ResultIsExpected(string initial, string largest, string expected)
        {
            //Arrange
            var initialNumber = PacketNumber.Parse(Utils.ParseHexString(initial));
            var largestNumber = PacketNumber.Parse(Utils.ParseHexString(largest));
            var expectedNumber = PacketNumber.Parse(Utils.ParseHexString(expected));

            //Act
            var resultNumber = initialNumber.EncodeByLargestAcknowledged(largestNumber);

            //Assert
            Assert.Equal(expectedNumber, resultNumber);
        }
    }
}
