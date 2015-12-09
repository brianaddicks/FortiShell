using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Web;

namespace FortiShell {
	
    public class Vip {
		public string Name;
		public string ExternalInterface;
		public string ExternalIp;
		public string MappedIp;
    }
}