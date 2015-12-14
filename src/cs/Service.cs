using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Web;

namespace FortiShell {
	
    public class Service {
		public string Name;
		public List<string> Value;
		public string Comment;
		public string Category;
    }
}