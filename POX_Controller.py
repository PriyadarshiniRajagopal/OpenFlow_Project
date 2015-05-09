from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from pox.lib.revent import EventRemove

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5


class Entry (object):


  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    self.fakeways = set(fakeways)
    self.arp_for_unknowns = arp_for_unknowns
    self.outstanding_arps = {}
    self.lost_buffers = {}
    self.ip_mac_port = {}
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)
    self.listenTo(core)

  def _handle_expiration (self):
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.ip_mac_port:
      self.ip_mac_port[dpid] = {}
      for fake in self.fakeways:
        self.ip_mac_port[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      if packet.next.srcip in self.ip_mac_port[dpid]:
        if self.ip_mac_port[dpid][packet.next.srcip] != (inport, packet.src):
          log.debug("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        #log.info("%i %i learned %s", dpid,inport,str(packet.next.srcip))
        log.info("switch %i learned %s from input port %i", dpid,str(packet.next.srcip),inport)
      self.ip_mac_port[dpid][packet.next.srcip] = Entry(inport, packet.src)

      dstaddr = packet.next.dstip
      if dstaddr in self.ip_mac_port[dpid]:

        prt = self.ip_mac_port[dpid][dstaddr].port
        mac = self.ip_mac_port[dpid][dstaddr].mac
        print dstaddr
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))
          
          if event.ofp.buffer_id==None:
             bid = None 
          else:
             bid = event.ofp.buffer_id
          
          ip_packet=packet.find("ipv4")
          if ip_packet!=None:
                            
             if ip_packet.protocol==1: 
                actions3 = []
         	actions3.append(of.ofp_action_dl_addr.set_dst(mac))
     		#actions3.append(of.ofp_action_output(port = prt))
      		actions3.append(of.ofp_action_enqueue(port = prt,queue_id=1))
    		match3 = of.ofp_match.from_packet(packet, inport)
     		match3.dl_type=0x800
    		match3.nw_proto = 1
    		match3.dl_src = None
     		msg3 = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=bid,
                                actions=actions3, priority=30,
                                match=match3)
        	event.connection.send(msg3.pack())
                print "into queue 1"
             elif ip_packet.protocol==17 or ip_packet.protocol==6: 
                udp_packet=packet.find("udp")
                if udp_packet==None:
                   udp_packet=packet.find("tcp")
		if ip_packet.dstip==IPAddr("172.16.0.3") and udp_packet.dstport==5001:
		   actions5 = []
		   actions5.append(of.ofp_action_dl_addr.set_dst(mac))
		   #actions5.append(of.ofp_action_output(port = prt))
		   actions5.append(of.ofp_action_enqueue(port = prt,queue_id=3))
	 	   match5 = of.ofp_match.from_packet(packet, inport)
		   match5.dl_type=0x800
		   match5.nw_proto = 17
		   match5.nw_dst = IPAddr("172.16.0.3")
		   match5.tp_dst = 5001
		   match5.dl_src = None
		   msg5 = of.ofp_flow_mod(command=of.OFPFC_ADD,
				                idle_timeout=FLOW_IDLE_TIMEOUT,
				                hard_timeout=of.OFP_FLOW_PERMANENT,
				                buffer_id=bid,
				                actions=actions5, priority=43,
				                match=match5)
		   event.connection.send(msg5.pack())
                   print "privillaged user into queue 3"
                elif ip_packet.tos==0:
                   actions2 = []
        	   actions2.append(of.ofp_action_dl_addr.set_dst(mac))
      		   #actions2.append(of.ofp_action_output(port = prt))
     		   actions2.append(of.ofp_action_nw_tos(224))
          	   actions2.append(of.ofp_action_enqueue(port = prt,queue_id=2))
          	   match2 = of.ofp_match.from_packet(packet, inport)
         	   match2.dl_type=0x800
                   if udp_packet!=None:
         	      match2.nw_proto = 17
                   else:
                      match2.nw_proto = 6
          	   match2.dl_src = None
          	   msg2 = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=bid,
                                actions=actions2, priority=42,
                                match=match2)
         	   event.connection.send(msg2.pack())
                   print "into queue 2"
                else:
                   actions1 = []
       		   actions1.append(of.ofp_action_dl_addr.set_dst(mac))
     		   #actions1.append(of.ofp_action_output(port = prt))
         	   actions1.append(of.ofp_action_enqueue(port = prt,queue_id=2))
          	   match1 = of.ofp_match.from_packet(packet, inport)
          	   match1.dl_type=0x800
          	   match1.nw_tos = 224
          	   match1.dl_src = None
          	   msg1 = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=bid,
                                actions=actions1, priority=42,
                                match=match1)
          	   event.connection.send(msg1.pack())
                   print "into queue 2 dscp tagged"
          else:
             actions = []
             actions.append(of.ofp_action_dl_addr.set_dst(mac))
             actions.append(of.ofp_action_output(port = prt))
             match4 = of.ofp_match.from_packet(packet, inport)
             match4.dl_src = None # Wildcard source MAC

             msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=bid,
                                actions=actions, priority=20,
                                match=match4)
             event.connection.send(msg.pack())

          




      elif self.arp_for_unknowns:
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        if (dpid,dstaddr) in self.outstanding_arps:
          return

        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.ip_mac_port[dpid]:
              if self.ip_mac_port[dpid][a.protosrc] != (inport, packet.src):
                log.debug("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.info("switch %i learned %s from input port %i", dpid,str(a.protosrc),inport)
            self.ip_mac_port[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.ip_mac_port[dpid]:
                # We have an answer...

                if not self.ip_mac_port[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.ip_mac_port[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  #log.debug("%i %i answering ARP for %s" % (dpid, inport,str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)


def launch (fakeways="", arp_for_unknowns=None):
  def set_miss_length (event = None):
    if not core.hasComponent('openflow'):
      return
    core.openflow.miss_send_len = 0x7fff
    core.getLogger().info("Requesting full packet payloads")
    return EventRemove
    
  if set_miss_length() is None:
    core.addListenerByName("ComponentRegistered", set_miss_length)

  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)

