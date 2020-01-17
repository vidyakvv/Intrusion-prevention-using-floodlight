package net.floodlightcontroller.ips;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.TableId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.projectfloodlight.openflow.types.EthType;

public class IPS implements IFloodlightModule, IOFMessageListener, Runnable {

	protected IOFSwitchService switchService;
	private static final int INFINITE_TIMEOUT = 0;
	protected static Logger logger;
	static int VAL_IPv4 = 0x0800;
	protected IFloodlightProviderService floodlightProviderService;
	IOFSwitch sw;
	Ethernet eth;
	
	

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "ips1";
	}
	
	public IPS(){
		
	}
	
	public IPS(IOFSwitch my_switch, Ethernet eth){
		this.sw = my_switch;
		this.eth = eth;
	}

	/*
	 * public Ips1() { //String timerEventGen="TimerEventGen"; Thread
	 * timerEventGenThread = new Thread(this);
	 * System.out.println("Thread Started"); timerEventGenThread.start(); }
	 */

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		IPS runner = new IPS(sw, eth);

		Thread thread = new Thread(runner);
		thread.start();
		// TODO Auto-generated method stub

		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context
				.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(IPS.class);
		// TODO Auto-generated method stub
		

		/*
		 * Thread thread = new Thread(this); thread.start();
		 */
	}

	@Override
	public void run() {
		
		// TODO Auto-generated method stub
		while (true) {
			try {
				// Query switchService to check if the switch is up, running
				// & controllable
				Thread.sleep(30000);

				logger.info("************* checking the file*****************");

				Checkfile(sw, eth);
				logger.info("*************Restarting thread*****************");
				// Thread.sleep(1000);

			}

			catch (InterruptedException e) {
				logger.info("************* Error in thread *****************");
				e.printStackTrace();
			}
		}

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		// TODO Auto-generated method stub

	}

	public void Checkfile(IOFSwitch sw, Ethernet eth) {

		File snortAlertLog = new File(
				"/home/mininet/floodlight/src/main/java/net/floodlightcontroller/ips/alertlog.log");
		Pattern ipExtract = Pattern
				.compile(".*\\{([a-zA-Z]+)\\} (.*?) -> (.*?)$");
		logger.info("File Length: " + snortAlertLog.length());

		if (snortAlertLog.length() != 0) {
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
						logger.info("****Protocol: " + protocol
								+ "****SourceIp:  " + sourceIp
								+ "******DestinationIp: " + destinationIp);
						if (protocol.equals("ICMP")) {
							short NUM_ICMP = 0x01;
							IPv4Address src_ip = IPv4Address.of(sourceIp);
							IPv4Address dst_ip = IPv4Address.of(destinationIp);
							IpProtocol ip_proto = IpProtocol.of(NUM_ICMP);

							Match match = sw.getOFFactory().buildMatch()
									.setExact(MatchField.IPV4_DST, dst_ip)
									.setExact(MatchField.IPV4_SRC, src_ip)
									.setExact(MatchField.IP_PROTO, ip_proto)
									.setExact(MatchField.ETH_TYPE, EthType.of(VAL_IPv4))
									.build();
							logger.info("*********** Match created*************");

							OFActions ofActions = sw.getOFFactory().actions();

							OFActionOutput output = ofActions.buildOutput()
									.build();
							ArrayList<OFAction> actionList = new ArrayList<OFAction>();
							actionList.add(output);
							logger.info("*********** Creating Flow Mod*************");
							OFFlowAdd dropflow = sw.getOFFactory()
									.buildFlowAdd()
									.setBufferId(OFBufferId.NO_BUFFER)
									.setHardTimeout(INFINITE_TIMEOUT)
									.setIdleTimeout(INFINITE_TIMEOUT)
									.setPriority(Integer.MAX_VALUE)
									.setTableId(TableId.of(0)).setMatch(match)
									.setActions(actionList).build();
							logger.info("*********** Flow Mod created*************");
							//Ethernet eth = new Ethernet();
							/*eth.setSourceMACAddress(MacAddress
									.of("00:00:00:00:00:01"));*/
							logger.info("Drop Flow: " + dropflow.toString());
							sw.write(dropflow);
							logger.info("***********Writing flow mod to Switch stream *************");
							//OFPort inPort = OFPort.IN_PORT;
							OFPacketOut packetOut = sw.getOFFactory()
									.buildPacketOut().setData(eth.serialize())
									.setActions(actionList)
									.build();
							logger.info("***********Creating Packet Out *************");

							logger.info("packet out: " + packetOut.toString());
							sw.write(packetOut);
							logger.info("***********Sent Packet Out *************");

						} else if (protocol.equals("TCP")) {
							short NUM_TCP = 0x06;
							sourceIp = sourceIp.split(":")[0];
							destinationIp = destinationIp.split(":")[0];
							IPv4Address src_ip = IPv4Address.of(sourceIp);
							IPv4Address dst_ip = IPv4Address.of(destinationIp);
							IpProtocol ip_proto = IpProtocol.of(NUM_TCP);

							Match match = sw.getOFFactory().buildMatch()
									.setExact(MatchField.IPV4_DST, dst_ip)
									.setExact(MatchField.IPV4_SRC, src_ip)
									.setExact(MatchField.IP_PROTO, ip_proto)
									.setExact(MatchField.ETH_TYPE, EthType.of(VAL_IPv4))
									.build();
							logger.info("*********** Match created*************");

							OFActions ofActions = sw.getOFFactory().actions();

							OFActionOutput output = ofActions.buildOutput()
									.build();
							ArrayList<OFAction> actionList = new ArrayList<OFAction>();
							actionList.add(output);
							logger.info("*********** Creating Flow Mod*************");
							OFFlowAdd dropflow = sw.getOFFactory()
									.buildFlowAdd()
									.setBufferId(OFBufferId.NO_BUFFER)
									.setHardTimeout(INFINITE_TIMEOUT)
									.setIdleTimeout(INFINITE_TIMEOUT)
									.setPriority(Integer.MAX_VALUE)
									.setTableId(TableId.of(0)).setMatch(match)
									.setActions(actionList).build();
							logger.info("*********** Flow Mod created*************");
							//Ethernet eth = new Ethernet();
							/*eth.setSourceMACAddress(MacAddress
									.of("00:00:00:00:00:01"));*/
							logger.info("Drop Flow: " + dropflow.toString());
							sw.write(dropflow);
							logger.info("***********Writing flow mod to Switch stream *************");
							//OFPort inPort = OFPort.IN_PORT;
							OFPacketOut packetOut = sw.getOFFactory()
									.buildPacketOut().setData(eth.serialize())
									.setActions(actionList)
									.build();
							logger.info("***********Creating Packet Out *************");

							logger.info("packet out: " + packetOut.toString());
							sw.write(packetOut);
							logger.info("***********Sent Packet Out *************");

							
						}

						sc.close();
						PrintWriter writer;
						writer = new PrintWriter(snortAlertLog);
						writer.print("");
						writer.close();
						logger.info("************** Alerts processed. Clearing the file***********************");
					}

				} else {
					sc.close();
				}

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
		} else {
			logger.info("*******************No content in alert log************************************");

		}

	}
}
