using System;
using System.Net;

namespace SharpBroadlink.Devices
{
	public class Dooya : Device
	{
		public Dooya(IPEndPoint host, byte[] mac, int devType) : base(host, mac, devType)
		{
			DeviceType = DeviceType.Dooya;

			throw new NotImplementedException(@"if you want: https://github.com/mjg59/python-broadlink/blob/56b2ac36e5a2359272f4af8a49cfaf3e1891733a/broadlink/__init__.py#L801-L845");
		}
	}
}