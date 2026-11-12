/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.server;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import org.junit.jupiter.api.Test;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * @author Eddú Meléndez
 */
public class UnboundIdContainerTests {

	@Test
	public void startLdapServer() throws Exception {
		UnboundIdContainer server = new UnboundIdContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		server.setApplicationContext(new GenericApplicationContext());
		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		try {
			server.afterPropertiesSet();
			assertThat(server.getPort()).isEqualTo(ports.get(0));
		}
		finally {
			server.destroy();
		}
	}

	@Test
	public void startLdapServerThenListenerBindsToLoopbackAddressOnly() throws Exception {
		UnboundIdContainer server = new UnboundIdContainer("dc=springframework,dc=org", null);
		server.setApplicationContext(new GenericApplicationContext());
		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		try {
			server.afterPropertiesSet();
			InMemoryDirectoryServer directoryServer = (InMemoryDirectoryServer) ReflectionTestUtils.getField(server,
					"directoryServer");
			assertThat(directoryServer.getListenAddress().isLoopbackAddress()).isTrue();
		}
		finally {
			server.destroy();
		}
	}

	@Test
	public void startLdapServerThenAdminBindFromNonLoopbackAddressIsRefused() throws Exception {
		InetAddress nonLoopbackAddress = getNonLoopbackAddress();
		assumeThat(nonLoopbackAddress).isNotNull();
		UnboundIdContainer server = new UnboundIdContainer("dc=springframework,dc=org", null);
		server.setApplicationContext(new GenericApplicationContext());
		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		try {
			server.afterPropertiesSet();
			String loopbackHost = InetAddress.getLoopbackAddress().getHostAddress();
			String nonLoopbackHost = nonLoopbackAddress.getHostAddress();
			int port = server.getPort();
			try (LDAPConnection connection = bindAsAdmin(loopbackHost, port)) {
				assertThat(connection.isConnected()).isTrue();
			}
			assertThatExceptionOfType(LDAPException.class).isThrownBy(() -> bindAsAdmin(nonLoopbackHost, port));
		}
		finally {
			server.destroy();
		}
	}

	@Test
	public void afterPropertiesSetWhenPortIsZeroThenRandomPortIsSelected() throws Exception {
		UnboundIdContainer server = new UnboundIdContainer("dc=springframework,dc=org", null);
		server.setPort(0);

		try {
			server.afterPropertiesSet();
			assertThat(server.getPort()).isNotEqualTo(0);
		}
		finally {
			server.destroy();
		}
	}

	private List<Integer> getDefaultPorts(int count) throws IOException {
		List<ServerSocket> connections = new ArrayList<>();
		List<Integer> availablePorts = new ArrayList<>(count);
		try {
			for (int i = 0; i < count; i++) {
				ServerSocket socket = new ServerSocket(0);
				connections.add(socket);
				availablePorts.add(socket.getLocalPort());
			}
			return availablePorts;
		}
		finally {
			for (ServerSocket conn : connections) {
				conn.close();
			}
		}
	}

	private LDAPConnection bindAsAdmin(String host, int port) throws LDAPException {
		return new LDAPConnection(host, port, "uid=admin,ou=system", "secret");
	}

	private InetAddress getNonLoopbackAddress() throws SocketException {
		for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
			if (!networkInterface.isUp() || networkInterface.isLoopback()) {
				continue;
			}
			for (InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
				if (address instanceof Inet4Address && !address.isLoopbackAddress()) {
					return address;
				}
			}
		}
		return null;
	}

}
