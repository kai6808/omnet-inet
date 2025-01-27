#ifndef __INET_SIMBRICKSADAPTER_H
#define __INET_SIMBRICKSADAPTER_H

#include "inet/common/packet/printer/PacketPrinter.h"

namespace inet {

extern "C" {
#include <simbricks/netif/netif.h>
#include <simbricks/proto/network.h>
}

class INET_API SimbricksAdapter : public cSimpleModule{

    protected:
        enum Kinds { SYNC_EVENT, POLL_EVENT };
        std::string device;
        const char *packetNameFormat = nullptr;

        int numSent = 0;
        int numReceived = 0;

        PacketPrinter packetPrinter;

    protected:
        virtual void initialize() override;
        virtual void handleMessage(cMessage *msg) override;
        virtual void finish() override;
    
    public:
        virtual ~SimbricksAdapter();
        // virtual bool notify(int fd) override;
        bool notify(int fd);

        std::string m_uxSocketPath;
        SimTime m_syncDelay;
        SimTime m_pollDelay;
        SimTime m_ethLatency;
        int m_sync;
    
    private:
        struct SimbricksNetIf *m_nsif;
        bool m_isConnected;
        SimTime m_nextTime;
        cMessage *m_syncTxEvent = nullptr;
        cMessage *m_pollEvent = nullptr;

        void ReceivedPacket (const void *buf, size_t len);
        volatile union SimbricksProtoNetN2D *AllocTx ();
        bool Poll ();
        void PollEvent ();
        void SendSyncEvent ();

    };

} //namespace inet

#endif //__INET_SIMBRICKSADAPTER_H