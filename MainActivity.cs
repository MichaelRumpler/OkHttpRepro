using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;

using Android.App;
using Android.OS;
using Android.Widget;

using Java.Interop;
using Java.Security;
using Java.Security.Cert;
using Javax.Net.Ssl;

using Square.OkHttp;
using System.Threading.Tasks;
using System.Text;

namespace OkHttpRepro
{
	[Activity(Label = "OkHttpRepro", MainLauncher = true, Icon = "@drawable/icon")]
	public class MainActivity : Activity
	{
		Button downloadBtn;
		Button clearBtn;
		TextView result;
		TextView status;

		protected override void OnCreate(Bundle bundle)
		{
			base.OnCreate(bundle);

			// Set our view from the "main" layout resource
			SetContentView(Resource.Layout.Main);

			downloadBtn = FindViewById<Button>(Resource.Id.downloadButton);
			clearBtn = FindViewById<Button>(Resource.Id.clearButton);
			result = FindViewById<TextView>(Resource.Id.result);
			status = FindViewById<TextView>(Resource.Id.status);

			downloadBtn.Click += DownloadBtn_Click;
			clearBtn.Click += Clear_Click;
		}

		private async void DownloadBtn_Click(object sender, EventArgs e)
		{
			//var handler = new NativeMessageHandler(false, true);
			//var client = new HttpClient(handler);

			var st = new Stopwatch();

			//handler.DisableCaching = true;

			st.Start();
			try
			{
				//var url = "https://self-signed.badssl.com/";					// works
				var url = "https://code4ward.ddns.net:54899/status";            // stream was reset: PROTOCOL_ERROR

				var resp = await HttpGet(url);
				result.Text = "Got the headers!";

				status.Text = string.Format("HTTP {0}: {1}", (int)resp.StatusCode, resp.ReasonPhrase);

				var sb = new StringBuilder();
				foreach (var v in resp.Headers)
					sb.AppendFormat("{0}: {1}\n", v.Key, String.Join(",", v.Value));
				sb.AppendLine();

				var stream = await resp.Content.ReadAsStreamAsync();

				var ms = new MemoryStream();
				await stream.CopyToAsync(ms, 4096);
				var bytes = ms.ToArray();

				sb.Append($"Body has {bytes.Length} bytes.");

				result.Text = sb.ToString();
			}
			catch (Exception ex)
			{
				result.Text = ex.ToString();
			}
			finally
			{
				st.Stop();
				result.Text = (result.Text ?? "") + String.Format("\n\nTook {0} milliseconds", st.ElapsedMilliseconds);
			}
		}

		private async Task<HttpResponseMessage> HttpGet(string url)
		{
			var client = new OkHttpClient();
			client.SetHostnameVerifier(new HostnameVerifier());
			client.SetSslSocketFactory(GetSocketFactory());

			var builder = new Request.Builder()
				.Method("GET", null)
				.Url(url)
				.CacheControl(new CacheControl.Builder().NoCache().Build())
				.AddHeader("User-Agent", "Test/1.0");

			var rq = builder.Build();
			var call = client.NewCall(rq);

			System.Diagnostics.Debug.WriteLine("Sending Call...");

			var resp = await call.EnqueueAsync().ConfigureAwait(false);

			System.Diagnostics.Debug.WriteLine("Got response");

			var respBody = resp.Body();

			var ret = new HttpResponseMessage((HttpStatusCode)resp.Code());
			ret.ReasonPhrase = resp.Message();
			if (respBody != null)
				ret.Content = new StreamContent(respBody.ByteStream());
			else
				ret.Content = new ByteArrayContent(new byte[0]);

			var respHeaders = resp.Headers();
			foreach (var k in respHeaders.Names())
			{
				ret.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
				ret.Content.Headers.TryAddWithoutValidation(k, respHeaders.Get(k));
			}

			return ret;
		}

		private void Clear_Click(object sender, EventArgs e)
		{
			result.Text = string.Empty;
		}

		private SSLSocketFactory GetSocketFactory()
		{
			// Create an SSLContext that uses our TrustManager
			var context = SSLContext.GetInstance("TLSv1.2");
			context.Init(null, new ITrustManager[] { new CustomX509TrustManager() }, null);

			// return the final socket factory
			return context.SocketFactory;
		}
	}

	class HostnameVerifier : Java.Lang.Object, IHostnameVerifier
	{
		public bool Verify(string hostname, ISSLSession session)
		{
			System.Diagnostics.Debug.WriteLine("HostnameVerifier.Verify returns true");
			return true;
		}
	}

	public class CustomX509TrustManager : Java.Lang.Object, IX509TrustManager
	{
		private readonly IX509TrustManager defaultTrustManager;

		public CustomX509TrustManager()
		{
			var algorithm = TrustManagerFactory.DefaultAlgorithm;
			var defaultTrustManagerFactory = TrustManagerFactory.GetInstance(algorithm);
			defaultTrustManagerFactory.Init((KeyStore)null);
			var trustManagers = defaultTrustManagerFactory.GetTrustManagers();
			defaultTrustManager = trustManagers[0].JavaCast<IX509TrustManager>();
		}

		public void CheckClientTrusted(Java.Security.Cert.X509Certificate[] chain, string authType)
		{
			// we are the client
		}

		public void CheckServerTrusted(Java.Security.Cert.X509Certificate[] certificates, string authType)
		{
			System.Diagnostics.Debug.WriteLine("In CustomX509TrustManager.CheckServerTrusted");

			try
			{
				defaultTrustManager.CheckServerTrusted(certificates, authType);
				System.Diagnostics.Debug.WriteLine($"defaultTrustManager trusted");
			}
			catch (CertificateException)
			{
				System.Diagnostics.Debug.WriteLine("defaultTrustManager did not trust");
				System.Diagnostics.Debug.WriteLine("CustomX509TrustManager does (after some checks)");
			}
		}

		Java.Security.Cert.X509Certificate[] IX509TrustManager.GetAcceptedIssuers()
		{
			return new Java.Security.Cert.X509Certificate[0];
		}
	}

	public static class AwaitableOkHttp
	{
		public static Task<Response> EnqueueAsync(this Call This)
		{
			var cb = new OkTaskCallback();
			This.Enqueue(cb);

			return cb.Task;
		}

		class OkTaskCallback : Java.Lang.Object, ICallback
		{
			readonly TaskCompletionSource<Response> tcs = new TaskCompletionSource<Response>();
			public Task<Response> Task { get { return tcs.Task; } }

			public void OnFailure(Request p0, Java.IO.IOException p1)
			{
				// Kind of a hack, but the simplest way to find out that server cert. validation failed
				if (p1.Message == String.Format("Hostname '{0}' was not verified", p0.Url().Host))
				{
					tcs.TrySetException(new WebException(p1.LocalizedMessage, WebExceptionStatus.TrustFailure));
				}
				else if (p1.Message.ToLowerInvariant().Contains("canceled"))
				{
					tcs.TrySetException(new System.OperationCanceledException());
				}
				else
				{
					tcs.TrySetException(new WebException(p1.Message));
				}
			}

			public void OnResponse(Response p0)
			{
				tcs.TrySetResult(p0);
			}
		}
	}
}

