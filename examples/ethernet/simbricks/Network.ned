package inet.examples.ethernet.simbricks;


import inet.common.misc.ThruputMeteringChannel;
import inet.linklayer.ethernet.EtherBus;
import inet.linklayer.ethernet.EtherHub;
import inet.linklayer.simbricks.simbricksEthernetInterface;
import inet.node.ethernet.EtherHost;
import inet.node.ethernet.EtherSwitch;
import inet.node.ethernet.SimbricksEtherHost;
import ned.DatarateChannel;

//for now only support 2-port case

network SingleSwitch{

    submodules:
        switch: EtherSwitch{
            parameters:
                @display("p=250,200");
            gates:
                ethg[2];
        }
    connections allowunconnected:
    
}

// two hosts connected to a switch
network twoHostoneSwitch{
    types:
        channel C extends DatarateChannel
        {
            delay = 0us;
            datarate = 100Gbps;
        }

    submodules:
        hostA: SimbricksEtherHost {
            parameters:
                @display("p=250,100");
        }
        hostB: SimbricksEtherHost {
            parameters:
                @display("p=400,200");
        }
        
        switch: EtherSwitch{
            parameters:
                @display("p=250,200");
            gates:
                ethg[2];
        }
    
    connections:
        switch.ethg[0] <--> C <--> hostA.ethg;
        switch.ethg[1] <--> C <--> hostB.ethg;

}
