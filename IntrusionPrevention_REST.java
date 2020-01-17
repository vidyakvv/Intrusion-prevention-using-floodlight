// Author: Vidya
// SJSU CMPE210

package edu.sjsu.ips;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.simple.JSONObject;

public class IntrusionPrevention {

	// http://localhost:8080/RESTfulExample/json/product/post
	public static void main(String[] args) throws Exception {
		{
			while (true) {
				File snortAlertLog = new File(
						"/home/mininet/Java_project/intrusion_prevention/src/main/java/edu/sjsu/ips/alertLog.log");

				Pattern ipExtract = Pattern
						.compile(".*\\{([a-zA-Z]+)\\} (.*?) -> (.*?)$");
				String jsonString = null;

				// Check if the file is not empty
				System.out.println("File Length: " + snortAlertLog.length());
				if (snortAlertLog.length() != 0) {

					// 05/05-21:00:37.997479 [**] [1:1000002:0] Possible TCP DoS
					// [**] [Classification: A TCP connection was detected]
					// [Priority: 4] {TCP} 10.0.0.1:1347 -> 10.0.0.2:80

					// https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html
					// 05/03-12:45:18.009692 [**] [1:1000001:1] ”ICMP test” [**]
					// [Classification:
					// Generic ICMP event] [Priority: 3] {ICMP} 10.0.0.1 ->
					// 10.0.0.2

					Scanner sc;
					try {
						sc = new Scanner(snortAlertLog);
						String line = sc.nextLine();
						if (line.matches(".*Caught Int-Signal.*")) {
							line = sc.nextLine();
						}

						if (!line.isEmpty()) {

							Matcher matcher = ipExtract.matcher(line);
							if (matcher.matches()) {
								String protocol = matcher.group(1);
								String sourceIp = matcher.group(2);
								String destinationIp = matcher.group(3);



								// Create JSON like below
								/*
								 * 
								 * { "priority": "25000", "active": "true",
								 * "switch": "00:00:00:00:00:00:00:01",
								 * "cookie": "0", "name": 1, "hard_timeout":
								 * "0", "ip_proto": "0x01", "eth_type":
								 * "0x0800", "ipv4_src": "10.0.0.1", "ipv4_dst":
								 * "10.0.0.2" }
								 */
								JSONObject json = new JSONObject();
								if (protocol.equals("ICMP")) {

									json.put("ipv4_src", sourceIp);
									json.put("ipv4_dst", destinationIp);
									json.put("priority", "25000");
									json.put("active", "true");
									json.put("cookie", "0");
									json.put("name", 1);
									json.put("hard_timeout", "0");
									json.put("ip_proto", "0x01");
									json.put("eth_type", "0x0800");
									json.put("switch",
											"00:00:00:00:00:00:00:01");
								} else if (protocol.equals("TCP")) {
									sourceIp = sourceIp.split(":")[0];
									destinationIp = destinationIp.split(":")[0];
									json.put("ipv4_src", sourceIp);
									json.put("ipv4_dst", destinationIp);
									json.put("priority", "25000");
									json.put("active", "true");
									json.put("cookie", "0");
									json.put("name", 2);
									json.put("hard_timeout", "0");
									json.put("ip_proto", "0x06");
									json.put("eth_type", "0x0800");
									json.put("switch",
											"00:00:00:00:00:00:00:01");
								}
								System.out.println("Protocol : " + protocol);
								System.out.println("Source IP : " + sourceIp);
								System.out.println("destinationIp : "
										+ destinationIp);

								jsonString = json.toJSONString();

								System.out.println("Json String : "
										+ jsonString);

								/*
								 * { "priority": "25000", "active": "true",
								 * "switch": "00:00:00:00:00:00:00:01",
								 * "cookie": "0", "name": 1, "hard_timeout":
								 * "0", "ip_proto": "0x01", "eth_type":
								 * "0x0800", "ipv4_src": "10.0.0.1", "ipv4_dst":
								 * "10.0.0.2" }
								 */

								sc.close();
								PrintWriter writer;
								writer = new PrintWriter(snortAlertLog);
								writer.print("");
								writer.close();
								try {

									DefaultHttpClient httpClient = new DefaultHttpClient();
									HttpPost postRequest = new HttpPost(
											"http://192.168.56.104:8080/wm/staticflowpusher/json");

									postRequest.setHeader("Content-type",
											"application/json");
									postRequest.setHeader("Accept",
											"application/json");

									StringEntity input = new StringEntity(
											jsonString);
									input.setContentType("application/json");

									postRequest.setEntity(input);

									HttpResponse response = httpClient
											.execute(postRequest);

									System.out
											.println("Response : " + response);

									httpClient.getConnectionManager()
											.shutdown();

								} catch (MalformedURLException e) {

									e.printStackTrace();
								} catch (IOException e) {

									e.printStackTrace();

								}
							} else {
								sc.close();
							}
						}

					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();

					}

				} else {
					System.out.println("No content in alert log");
					Thread.sleep(10000);
				}
			}
		}
	}
}
