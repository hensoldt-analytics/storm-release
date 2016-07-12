/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.storm.kinesis.spout;

import java.io.Serializable;

public class ZkInfo implements Serializable {
    // comma separated list of zk connect strings to connect to zookeeper e.g. localhost:2181
    private final String zkUrl;
    // zk node under which to commit the sequence number of messages. e.g. /committed_sequence_numbers
    private final String zkNode;
    // zk session timeout in milliseconds
    private final Integer sessionTimeoutMs;
    // zk connection timeout in milliseconds
    private final Integer connectionTimeoutMs;
    // interval at which to commit offsets to zk in milliseconds
    private final Long commitIntervalMs;
    // number of retry attempts for zk
    private final Integer retryAttempts;
    // time to sleep between retries in milliseconds
    private final Integer retryIntervalMs;

    /**
     * Default constructor that uses defaults for a local setup
     */
    public ZkInfo () {
        this("localhost:2181", "/kinesisOffsets", 20000, 15000, 10000L, 3, 2000);
    }

    public ZkInfo (String zkUrl, String zkNode, Integer sessionTimeoutMs, Integer connectionTimeoutMs, Long commitIntervalMs, Integer retryAttempts, Integer
            retryIntervalMs) {
        this.zkUrl = zkUrl;
        this.zkNode = zkNode;
        this.sessionTimeoutMs = sessionTimeoutMs;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.commitIntervalMs = commitIntervalMs;
        this.retryAttempts = retryAttempts;
        this.retryIntervalMs = retryIntervalMs;
        validate();
    }

    public String getZkUrl() {
        return zkUrl;
    }

    public String getZkNode() {
        return zkNode;
    }

    public Integer getSessionTimeoutMs() {
        return sessionTimeoutMs;
    }

    public Integer getConnectionTimeoutMs() {
        return connectionTimeoutMs;
    }

    public Long getCommitIntervalMs() {
        return commitIntervalMs;
    }

    public Integer getRetryAttempts() {
        return retryAttempts;
    }

    public Integer getRetryIntervalMs() {
        return retryIntervalMs;
    }

    private void validate () {

        if (zkUrl == null || zkUrl.length() < 1) {
            throw new IllegalArgumentException("zkUrl must be specified to connect to zookeeper");
        }
        if (zkNode == null || zkNode.length() < 1) {
            throw new IllegalArgumentException("zkNode must be specified");
        }
        checkPositive(sessionTimeoutMs, "sessionTimeoutMs");
        checkPositive(connectionTimeoutMs, "connectionTimeoutMs");
        checkPositive(commitIntervalMs, "commitIntervalMs");
        checkPositive(retryAttempts, "retryAttempts");
        checkPositive(retryIntervalMs, "retryIntervalMs");
    }

    private void checkPositive (Integer argument, String name) {
        if (argument == null && argument <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
    private void checkPositive (Long argument, String name) {
        if (argument == null && argument <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    @Override
    public String toString() {
        return "ZkInfo{" +
                "zkUrl='" + zkUrl + '\'' +
                ", zkNode='" + zkNode + '\'' +
                ", sessionTimeoutMs=" + sessionTimeoutMs +
                ", connectionTimeoutMs=" + connectionTimeoutMs +
                ", commitIntervalMs=" + commitIntervalMs +
                ", retryAttempts=" + retryAttempts +
                ", retryIntervalMs=" + retryIntervalMs +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ZkInfo zkInfo = (ZkInfo) o;

        if (zkUrl != null ? !zkUrl.equals(zkInfo.zkUrl) : zkInfo.zkUrl != null) return false;
        if (zkNode != null ? !zkNode.equals(zkInfo.zkNode) : zkInfo.zkNode != null) return false;
        if (sessionTimeoutMs != null ? !sessionTimeoutMs.equals(zkInfo.sessionTimeoutMs) : zkInfo.sessionTimeoutMs != null) return false;
        if (connectionTimeoutMs != null ? !connectionTimeoutMs.equals(zkInfo.connectionTimeoutMs) : zkInfo.connectionTimeoutMs != null) return false;
        if (commitIntervalMs != null ? !commitIntervalMs.equals(zkInfo.commitIntervalMs) : zkInfo.commitIntervalMs != null) return false;
        if (retryAttempts != null ? !retryAttempts.equals(zkInfo.retryAttempts) : zkInfo.retryAttempts != null) return false;
        return !(retryIntervalMs != null ? !retryIntervalMs.equals(zkInfo.retryIntervalMs) : zkInfo.retryIntervalMs != null);

    }

    @Override
    public int hashCode() {
        int result = zkUrl != null ? zkUrl.hashCode() : 0;
        result = 31 * result + (zkNode != null ? zkNode.hashCode() : 0);
        result = 31 * result + (sessionTimeoutMs != null ? sessionTimeoutMs.hashCode() : 0);
        result = 31 * result + (connectionTimeoutMs != null ? connectionTimeoutMs.hashCode() : 0);
        result = 31 * result + (commitIntervalMs != null ? commitIntervalMs.hashCode() : 0);
        result = 31 * result + (retryAttempts != null ? retryAttempts.hashCode() : 0);
        result = 31 * result + (retryIntervalMs != null ? retryIntervalMs.hashCode() : 0);
        return result;
    }
}
