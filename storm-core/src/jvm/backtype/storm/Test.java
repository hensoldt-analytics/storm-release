package backtype.storm;

import backtype.storm.generated.Nimbus;
import backtype.storm.utils.NimbusClient;
import backtype.storm.utils.Utils;
import org.apache.thrift.TException;

import java.util.HashMap;
import java.util.Map;

import static backtype.storm.utils.Utils.readStormConfig;

/**
 * Created by pshah on 8/12/15.
 */
public class Test {
    public static void main(String args[]) throws TException {
        Map conf =  readStormConfig();
        conf.put(Config.NIMBUS_HOST, "c6402.ambari.apache.org");
        conf.put(Config.NIMBUS_THRIFT_PORT, 6627);
        conf.put(Config.NIMBUS_THRIFT_TRANSPORT_PLUGIN,
                        "backtype.storm.security.auth.SimpleTransportPlugin");
        NimbusClient client = NimbusClient.getConfiguredClient(conf);
        client.getClient().getClusterInfo();
    }
}
