﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SharpBroadlink.Devices;
using Xb.Net;

namespace SharpBroadlink
{
	public class Broadlink
	{
		public enum WifiSecurityMode
		{
			None = 0,
			Wep = 1,
			WPA1 = 2,
			WPA2 = 3,
			WPA12 = 4
		}

		public static async Task<List<IDevice>> Discover(int timeout = 0)
		{
			var result = new List<IDevice>();
			if (timeout == 0)
				await Discover(result);
			else
				using (var cancellationSource = new CancellationTokenSource(TimeSpan.FromSeconds(timeout)))
				{
					await Discover(result, null, cancellationSource.Token);
				}

			return result;
		}

        /// <summary>
        ///     Find devices on the LAN.
        /// </summary>
        /// <param name="devices">Devices result collection</param>
        /// <param name="cancellationToken">
        ///     Optional Cancellation Token. If not provided the method will exit after discovering at
        ///     least one device or after a timeout
        /// </param>
        /// <param name="localIpAddress"></param>
        /// <returns></returns>
        /// <remarks>
        ///     https://github.com/mjg59/python-broadlink/blob/56b2ac36e5a2359272f4af8a49cfaf3e1891733a/broadlink/__init__.py#L61-L138
        /// </remarks>
        public static async Task Discover(ICollection<IDevice> devices, IPAddress localIpAddress = null, CancellationToken cancellationToken = default)
		{
			if (localIpAddress == null)
				localIpAddress = IPAddress.Any;

			var address = localIpAddress.GetAddressBytes();
			if (address.Length != 4)
				throw new NotSupportedException("Not Supported IPv6");

			// for address endian validation
			var localPrimaryIpAddress = Util
				.GetLocalPrimaryAddress()
				.GetAddressBytes();

			using (var cs = new Udp())
			{
				var port = cs.LocalPort;
				var startTime = DateTime.Now;
				var timezone = (int) (TimeZoneInfo.Local.BaseUtcOffset.TotalSeconds / -3600);
				var year = startTime.Year;
				var subYear = year % 100;

				// 1=mon, 2=tue,... 7=sun
				var isoWeekday = startTime.DayOfWeek == DayOfWeek.Sunday
					? 7
					: (int) startTime.DayOfWeek;

				var packet = new byte[0x30];
				if (timezone < 0)
				{
					packet[0x08] = (byte) (0xff + timezone - 1);
					packet[0x09] = 0xff;
					packet[0x0a] = 0xff;
					packet[0x0b] = 0xff;
				}
				else
				{
					packet[0x08] = (byte) timezone;
					packet[0x09] = 0;
					packet[0x0a] = 0;
					packet[0x0b] = 0;
				}

				packet[0x0c] = (byte) (year & 0xff);
				packet[0x0d] = (byte) (year >> 8);
				packet[0x0e] = (byte) startTime.Minute;
				packet[0x0f] = (byte) startTime.Hour;
				packet[0x10] = (byte) subYear;
				packet[0x11] = (byte) isoWeekday;
				packet[0x12] = (byte) startTime.Day;
				packet[0x13] = (byte) startTime.Month;
				packet[0x18] = address[0];
				packet[0x19] = address[1];
				packet[0x1a] = address[2];
				packet[0x1b] = address[3];
				packet[0x1c] = (byte) (port & 0xff);
				packet[0x1d] = (byte) (port >> 8);
				packet[0x26] = 6;

				var checksum = 0xbeaf;
				foreach (var b in packet)
					checksum += b;

				checksum = checksum & 0xffff;

				packet[0x20] = (byte) (checksum & 0xff);
				packet[0x21] = (byte) (checksum >> 8);

				var isReceivedOnce = false;
				cs.OnRecieved += (sender, rdata) =>
				{
					// Get mac
					// 0x3a-0x3f, Little Endian
					var mac = new byte[6];
					Array.Copy(rdata.Bytes, 0x3a, mac, 0, 6);
					Array.Reverse(mac);

					// Get IP address
					byte[] addr;
					if (rdata.RemoteEndPoint.AddressFamily
						== AddressFamily.InterNetwork)
					{
						var tmpAddr = rdata.RemoteEndPoint.Address.GetAddressBytes();
						addr = tmpAddr.Skip(tmpAddr.Length - 4).Take(4).ToArray();
					}
					else if (rdata.RemoteEndPoint.AddressFamily
							== AddressFamily.InterNetworkV6)
					{
						// Get the IPv4 address in Broadlink-Device response.
						// 0x36-0x39, Mostly Little Endian
						addr = new byte[4];
						Array.Copy(rdata.Bytes, 0x36, addr, 0, 4);

						var sockAddr = rdata.RemoteEndPoint.Address.GetAddressBytes();
						var reverseAddr = rdata.RemoteEndPoint.Address.GetAddressBytes();

						// IPv4射影アドレスのとき、v4アドレスに変換。
						if (
							// 長さが16バイト
							sockAddr.Length == 16
							// 先頭10バイトが全て0
							&& sockAddr.Take(10).All(b => b == 0)
							// 11, 12バイトが FF
							&& sockAddr.Skip(10).Take(2).All(b => b == 255)
						)
						{
							sockAddr = sockAddr.Skip(12).Take(4).ToArray();
							reverseAddr = reverseAddr.Skip(12).Take(4).ToArray();
						}

						Array.Reverse(reverseAddr);


						if (sockAddr.SequenceEqual(addr))
						{
							// 1.v6アドレスの末尾4バイトと同一
							// 受信通りの並び順
						}
						else if (reverseAddr.SequenceEqual(addr))
						{
							// 2. v6アドレス末尾4バイトの逆順と同一
							// 逆順
							Array.Reverse(addr);
						}
						else if (addr[3] == localPrimaryIpAddress[0] && addr[2] == localPrimaryIpAddress[1])
						{
							// 3.ローカルv4アドレスの先頭2バイトが、逆順と合致
							// 恐らく逆順
							// Recieve IP address is Little Endian
							// Change to Big Endian.
							Array.Reverse(addr);
						}
					}
					else
					{
						Xb.Util.Out("Unexpected Address: " + BitConverter.ToString(rdata.RemoteEndPoint.Address.GetAddressBytes()));
						return;
					}

					var host = new IPEndPoint(new IPAddress(addr), 80);

					var devType = rdata.Bytes[0x34] | (rdata.Bytes[0x35] << 8);
					devices.Add(Factory.GenDevice(devType, host, mac));

					isReceivedOnce = true;
				};

				await cs.SendToAsync(packet, IPAddress.Broadcast, 80);

				try
				{
					await Task.Run(async () =>
					{
						while (true)
						{
							if (cancellationToken.Equals(CancellationToken.None) && (isReceivedOnce || (DateTime.Now - startTime).TotalSeconds > 10)
								|| cancellationToken.IsCancellationRequested)
								break;

							await Task.Delay(100).ConfigureAwait(false);
						}
					});
				}
				catch (TaskCanceledException)
				{
				}
				catch (OperationCanceledException)
				{
				}
			}
		}

        /// <summary>
        ///     Get IDevice object
        /// </summary>
        /// <param name="deviceType"></param>
        /// <param name="mac"></param>
        /// <param name="endPoint"></param>
        /// <returns></returns>
        public static IDevice Create(int deviceType, byte[] mac, IPEndPoint endPoint)
		{
			return Factory.GenDevice(deviceType, endPoint, mac);
		}

        /// <summary>
        ///     Set the Wi-Fi setting to devices.
        /// </summary>
        /// <param name="ssid"></param>
        /// <param name="password"></param>
        /// <param name="securityMode"></param>
        /// <remarks>
        ///     https://github.com/mjg59/python-broadlink/blob/56b2ac36e5a2359272f4af8a49cfaf3e1891733a/broadlink/__init__.py#L848-L883
        /// </remarks>
        public static async Task<bool> Setup(string ssid, string password, WifiSecurityMode securityMode)
		{
			var payload = new List<byte>();
			payload.AddRange(new byte[0x88]);

			payload[0x26] = 0x14;
			var ssidStart = 68;
			var ssidLength = 0;
			foreach (var schr in ssid)
			{
				payload[ssidStart + ssidLength] = (byte) schr;
				ssidLength++;
			}

			var passStart = 100;
			var passLength = 0;
			foreach (var pchar in password)
			{
				payload[passStart + passLength] = (byte) pchar;
				passLength++;
			}

			payload[0x84] = (byte) ssidLength;
			payload[0x85] = (byte) passLength;
			payload[0x86] = (byte) securityMode;

			var checksum = 0xbeaf;
			foreach (var b in payload)
			{
				checksum += b;
				checksum = checksum & 0xffff;
			}

			payload[0x20] = (byte) (checksum & 0xff);
			payload[0x21] = (byte) (checksum >> 8);

			await Udp.SendOnceAsync(payload.ToArray(), IPAddress.Broadcast, 80);

			return true;
		}
	}
}