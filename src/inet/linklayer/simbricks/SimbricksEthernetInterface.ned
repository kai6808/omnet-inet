
package inet.linklayer.simbricks;

import inet.emulation.common.ExtInterface;
import inet.linklayer.contract.IEtherMac;
import inet.linklayer.contract.IEthernetInterface;

module simbricksEthernetInterface extends ExtInterface like IEthernetInterface
{
    parameters:
        bool csmacdSupport = default(false);
        @display("i=block/ifcard");
    
    gates:
        inout phys @labels(EtherFrame);
    
    submodules:
        adapter: SimbricksAdapter{
            parameters:
                @display("p=100,100");
        }

        mac: <default(csmacdSupport ? "EtherMac" : "EtherMacFullDuplex")> like IEtherMac {
            parameters:
                queue.packetCapacity = 10000;
                @display("p=200,400");
        }
    
    connections allowunconnected:
        adapter.lowerLayerOut --> { @display("m=s"); } --> mac.upperLayerIn;
        adapter.lowerLayerIn <-- { @display("m=s"); } <-- mac.upperLayerOut;
        mac.phys <--> { @display("m=s"); } <--> phys;
}