
#include <iostream>
#include <csignal>

#include <omnetpp/platdep/sockets.h>

#ifndef  __linux__
#error The 'Network Emulation Support' feature currently works on Linux systems only
#else

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "inet/common/ModuleAccess.h"
#include "inet/common/NetworkNamespaceContext.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/ethernet/EtherEncap.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/linklayer/simbricks/SimbricksAdapter.h"


namespace inet {

Define_Module(SimbricksAdapter);

SimbricksAdapter::~SimbricksAdapter(){
    //delete cMessages and NetIf
    EV_INFO << "delete simbricks adapter\n";
}

void SimbricksAdapter::initialize(){
    

    int ret;
    int sync;

    m_sync = par("sync");
    m_syncDelay = SimTime(par("syncDelay"), SIMTIME_NS);
    m_pollDelay = SimTime(par("pollDelay"), SIMTIME_NS);
    m_ethLatency = SimTime(par("ethLatency"), SIMTIME_NS);

    std::cout << "m_syncDelay time resolution: " << m_syncDelay.getScaleExp() << std::endl;
    std::cout << "m_syncDelay raw: " << m_syncDelay.raw() << std::endl;
    std::cout << "m_pollDelay time resolution: " << m_pollDelay.getScaleExp() << std::endl;
    std::cout << "m_pollDelay raw: " << m_pollDelay.raw() << std::endl;
    std::cout << "m_ethLatency time resolution: " << m_ethLatency.getScaleExp() << std::endl;
    std::cout << "m_ethLatency raw: " << m_ethLatency.raw() << std::endl;

    m_nsif = new SimbricksNetIf;

    m_syncTxEvent = new cMessage("syncEvent", SYNC_EVENT);
    m_pollEvent = new cMessage("pollEvent", POLL_EVENT);

    sync = m_sync;

    std::cout << "Simbricks Adapter Initializing!\n";
    if ( !par("unixSoc").isSet() ){
        cRuntimeError("SimbricksAdapter::Connect: unix socket path empty\n");
    }

    m_uxSocketPath = par("unixSoc").stdstringValue();
    ret = SimbricksNetIfInit(m_nsif, m_uxSocketPath.c_str(), &sync);
    if ( ret != 0){
        cRuntimeError("SimbricksAdapter::Connect: SimbricksNetIfInit failed\n");
    }
    if (m_sync && !sync){
        cRuntimeError("SimbricksAdapter::Connect: Srequest for sync failed\n");
    }

    simtime_t t = simTime().getScaleExp();
    std::cout << "time scale: " << t << std::endl;
    if (m_sync){
        scheduleAt(simTime(), m_syncTxEvent);
    }

    scheduleAt(simTime(), m_pollEvent);
}


void SimbricksAdapter::ReceivedPacket (const void *buf, size_t len)
{   

    Packet *packet = new Packet(nullptr, makeShared<BytesChunk>((uint8_t*)buf, len));
    packet->insertAtBack(makeShared<EthernetFcs>(FCS_COMPUTED));  
    EV_INFO << "Received a packet from NIC\n";
    //PacketPrinter printer;
    //printer.printPacket(std::cout, packet); 
    send(packet, "lowerLayerOut");

}

bool SimbricksAdapter::Poll ()
{
    volatile union SimbricksProtoNetD2N *msg;
    uint8_t ty;
    

    msg = SimbricksNetIfD2NPoll (m_nsif, (uint64_t)simTime().raw());
    m_nextTime = SimTime(SimbricksNetIfD2NTimestamp (m_nsif), SIMTIME_PS); 

    if (!msg)
        return false;

    ty = msg->dummy.own_type & SIMBRICKS_PROTO_NET_D2N_MSG_MASK;
    switch (ty) {
        case SIMBRICKS_PROTO_NET_D2N_MSG_SEND:
            ReceivedPacket ((const void *) msg->send.data, msg->send.len);
            break;

        case SIMBRICKS_PROTO_NET_D2N_MSG_SYNC:
            break;

        default:
            cRuntimeError("SimbricksAdapter::Poll: unsupported message type %d\n", ty);
    }

    SimbricksNetIfD2NDone (m_nsif, msg);
    return true;
}


void SimbricksAdapter::PollEvent ()
{
    while (Poll ());

    if (m_sync){
        while (m_nextTime <= simTime())
            Poll ();

        //EV_INFO << "m_nextTime time resolution: " << m_nextTime.getScaleExp() << std::endl;
        //EV_INFO << "m_nextTime raw: " << m_nextTime.raw() << std::endl;
        scheduleAt(m_nextTime, m_pollEvent);

    } else {
        scheduleAt(simTime() + m_pollDelay, m_pollEvent);

    }
}


volatile union SimbricksProtoNetN2D *SimbricksAdapter::AllocTx ()
{
    volatile union SimbricksProtoNetN2D *msg;
    msg = SimbricksNetIfN2DAlloc (m_nsif, (uint64_t)simTime().raw(),
            (uint64_t)m_ethLatency.raw());

    if (msg == NULL){
        cRuntimeError("SimbricksAdapter::AllocTx: SimbricksNetIfN2DAlloc failed");
    }
    return msg;
}


void SimbricksAdapter::SendSyncEvent ()
{
    volatile union SimbricksProtoNetN2D *msg = AllocTx ();

    msg->sync.own_type = SIMBRICKS_PROTO_NET_N2D_MSG_SYNC |
        SIMBRICKS_PROTO_NET_N2D_OWN_DEV;

    scheduleAt(simTime() + m_syncDelay, m_syncTxEvent);
}



void SimbricksAdapter::handleMessage(cMessage *msg){
    
    if (msg->isSelfMessage()){
        //EV_INFO << "received serlfmessage\n";
        if (msg->getKind() == SYNC_EVENT){
            //EV_INFO << "received syncEvent\n";
            SendSyncEvent();
        }
        else if (msg->getKind() == POLL_EVENT){
            //EV_INFO << "received pollEvent\n";
            PollEvent();
            //scheduleAt(simTime() + 100, m_pollEvent);
        }
    }

    else{
        auto packet = check_and_cast<Packet *>(msg);
        auto protocol = packet->getTag<PacketProtocolTag>()->getProtocol();
        if (protocol != &Protocol::ethernetMac)
            throw cRuntimeError("Accepts ethernet packets only");
        
        const auto& ethHeader = packet->peekAtFront<EthernetMacHeader>();
        packet->popAtBack<EthernetFcs>(ETHER_FCS_BYTES);

        volatile union SimbricksProtoNetN2D *msg;
        volatile struct SimbricksProtoNetN2DRecv *recv;
        
        //EV_INFO << "Sent a " << packet->getTotalLength() << " packet from " << ethHeader->getSrc() << " to " << ethHeader->getDest() << endl;
        EV_INFO << "adapter sending " << packet << endl;

        msg = AllocTx ();
        recv = &msg->recv;

        //recv->len = (uint16_t)packet->getDataLength().get()/8;
        recv->len = (uint16_t)packet->getByteLength();
        EV_INFO << "recv->len set to " << recv->len << endl;
        recv->port = 0;

        uint8_t *buffer = (uint8_t *) recv->data;
        //buffer[0] = 0x08; // Ethernet
        //buffer[1] = 0x00;
        auto bytesChunk = packet->peekDataAsBytes();
        size_t packetLength = bytesChunk->copyToBuffer(buffer, packet->getByteLength());
        ASSERT(packetLength == (size_t)packet->getByteLength());

        recv->own_type = SIMBRICKS_PROTO_NET_N2D_MSG_RECV |
            SIMBRICKS_PROTO_NET_N2D_OWN_DEV;
        
        if (m_sync) {
            m_syncTxEvent = cancelEvent (m_syncTxEvent);
            scheduleAt(simTime() + m_syncDelay, m_syncTxEvent);
            
        }

        delete packet;

    }
}





bool SimbricksAdapter::notify(int fd){
    EV_INFO << "fd: " << fd; 
    return true;
}

void SimbricksAdapter::finish(){
    EV_INFO << "Goodbye World!\n";
}

} //namespace  inet

#endif // __linux__