
package inet.linklayer.simbricks;


simple SimbricksAdapter
{
    parameters:
        string device; //should change to shared memory absPath
        string namespace = default("");
        string unixSoc;
        int sync;
        int syncDelay = default(500);
        int pollDelay = default(500);
        int ethLatency = default(500);
        string packetNameFormat = default("Ext-%p-%t-%n");
        @display("i=block/rxtx");
    
    gates:
        input lowerLayerIn @labels(EtherFrame);
        output lowerLayerOut @labels(EtherFrame);

}