/*******************************************************************************
 * Copyright (c) 2010, 2014 Itema AS and others.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 *     Torkild U. Resheim - initial API and implementation
 *     Torkild U. Resheim - Uniquely identify Jenkins servers, bug 341725
 *     Torkild U. Resheim - Distinguish between Hudson and Jenkins, bug 353861
 *     Tasktop Technologies - improvements
 *******************************************************************************/

package org.eclipse.mylyn.internal.jenkins.ui;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.mylyn.builds.ui.BuildsUi;
import org.eclipse.mylyn.commons.core.StatusHandler;
import org.eclipse.mylyn.commons.repositories.core.RepositoryLocation;
import org.eclipse.osgi.util.NLS;

/**
 * This class implements a mechanism for discovering Jenkins servers through the use of Multicast DNS (MDNS).
 *
 * @author Torkild U. Resheim, Itema AS
 * @author Steffen Pingel
 */
public class JenkinsDiscovery {

	private static final String MDNS_ADDRESS = "224.0.0.251"; //$NON-NLS-1$

	private static final int MDNS_PORT = 5353;

	private static final String JENKINS_SERVICE_TYPE = "_jenkins._tcp.local"; //$NON-NLS-1$

	private static final String URL_PROPERTY = "url"; //$NON-NLS-1$

	/** Server id property name (Jenkins only). */
	private static final String SERVER_ID_PROPERTY = "server-id"; //$NON-NLS-1$

	private volatile boolean running;

	private Thread discoveryThread;

	private MulticastSocket socket;

	public JenkinsDiscovery() {
	}

	/**
	 * Determines whether or not the detected server is a new server or not.
	 *
	 * @param url
	 *            the server URL
	 * @param id
	 *            the server identifier
	 * @return <code>true</code> if the detected server is new.
	 */
	private boolean isNew(String url, String id) {
		if (url == null) {
			return false;
		}
		List<RepositoryLocation> locations = BuildsUi.getServerLocations();
		for (RepositoryLocation location : locations) {
			if (location.hasUrl(url) || location.getId().equals(id)) {
				return false;
			}
		}
		return true;
	}

	public void start() {
		if (running) {
			return;
		}
		running = true;
		discoveryThread = new Thread(this::runDiscovery, "Jenkins mDNS Discovery"); //$NON-NLS-1$
		discoveryThread.setDaemon(true);
		discoveryThread.start();
	}

	public void stop() {
		running = false;
		if (socket != null) {
			socket.close();
		}
		if (discoveryThread != null) {
			discoveryThread.interrupt();
			try {
				discoveryThread.join(1000);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			discoveryThread = null;
		}
	}

	private void runDiscovery() {
		try {
			InetAddress group = InetAddress.getByName(MDNS_ADDRESS);
			socket = new MulticastSocket(MDNS_PORT);
			
			// Join multicast group on all available network interfaces
			for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
				if (ni.isUp() && ni.supportsMulticast() && !ni.isLoopback()) {
					try {
						socket.joinGroup(new java.net.InetSocketAddress(group, MDNS_PORT), ni);
					} catch (IOException e) {
						// Some interfaces may not support multicast, continue with others
					}
				}
			}

			byte[] buffer = new byte[9000];
			DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

			while (running) {
				try {
					socket.receive(packet);
					processMdnsPacket(packet.getData(), packet.getLength());
				} catch (SocketException e) {
					if (running) {
						// Only log if we're still supposed to be running
						StatusHandler.log(new Status(IStatus.WARNING, JenkinsConnectorUi.ID_PLUGIN,
								"Error receiving mDNS packet", e)); //$NON-NLS-1$
					}
					break;
				} catch (IOException e) {
					if (running) {
						StatusHandler.log(new Status(IStatus.WARNING, JenkinsConnectorUi.ID_PLUGIN,
								"Error processing mDNS packet", e)); //$NON-NLS-1$
					}
				}
			}
		} catch (IOException e) {
			StatusHandler.log(
					new Status(IStatus.WARNING, JenkinsConnectorUi.ID_PLUGIN, Messages.Discovery_CouldNotStartService, e));
		} finally {
			if (socket != null) {
				socket.close();
			}
		}
	}

	private void processMdnsPacket(byte[] data, int length) {
		try {
			ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
			
			// Skip DNS header (12 bytes)
			if (buffer.remaining() < 12) {
				return;
			}
			buffer.position(12);

			// Read question section (skip it)
			int questionCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
			for (int i = 0; i < questionCount; i++) {
				skipName(buffer);
				if (buffer.remaining() < 4) {
					return;
				}
				buffer.getInt(); // Skip QTYPE and QCLASS
			}

			// Read answer section
			int answerCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
			for (int i = 0; i < answerCount; i++) {
				processRecord(buffer, data);
			}

			// Read additional section for TXT records with service properties
			int additionalCount = ((data[10] & 0xFF) << 8) | (data[11] & 0xFF);
			for (int i = 0; i < additionalCount; i++) {
				processRecord(buffer, data);
			}
		} catch (java.nio.BufferUnderflowException | IndexOutOfBoundsException e) {
			// Silently ignore malformed packets
		}
	}

	private void processRecord(ByteBuffer buffer, byte[] data) {
		String name = readName(buffer, data);
		if (buffer.remaining() < 10) {
			return;
		}

		int type = buffer.getShort() & 0xFFFF;
		buffer.getShort(); // Skip class
		buffer.getInt(); // Skip TTL
		int rdLength = buffer.getShort() & 0xFFFF;

		if (buffer.remaining() < rdLength) {
			return;
		}

		// Check if this is a TXT record (type 16) for Jenkins service
		if (type == 16 && name != null && name.contains(JENKINS_SERVICE_TYPE)) {
			byte[] rdata = new byte[rdLength];
			buffer.get(rdata);
			Map<String, String> properties = parseTxtRecord(rdata);
			handleJenkinsService(properties);
		} else {
			// Skip the record data
			buffer.position(buffer.position() + rdLength);
		}
	}

	private String readName(ByteBuffer buffer, byte[] data) {
		StringBuilder name = new StringBuilder();
		int jumps = 0;
		int savedPosition = -1;

		while (buffer.hasRemaining()) {
			int length = buffer.get() & 0xFF;
			if (length == 0) {
				break;
			}

			// Check for pointer (compression)
			if ((length & 0xC0) == 0xC0) {
				if (!buffer.hasRemaining()) {
					break;
				}
				int pointer = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
				if (savedPosition == -1) {
					savedPosition = buffer.position();
				}
				buffer.position(pointer);
				jumps++;
				if (jumps > 10) { // Prevent infinite loops
					break;
				}
				continue;
			}

			if (buffer.remaining() < length) {
				break;
			}

			if (name.length() > 0) {
				name.append('.');
			}

			byte[] label = new byte[length];
			buffer.get(label);
			name.append(new String(label, StandardCharsets.UTF_8));
		}

		if (savedPosition != -1) {
			buffer.position(savedPosition);
		}

		return name.toString();
	}

	private void skipName(ByteBuffer buffer) {
		while (buffer.hasRemaining()) {
			int length = buffer.get() & 0xFF;
			if (length == 0) {
				break;
			}
			if ((length & 0xC0) == 0xC0) {
				if (buffer.hasRemaining()) {
					buffer.get(); // Skip second byte of pointer
				}
				break;
			}
			if (buffer.remaining() < length) {
				break;
			}
			buffer.position(buffer.position() + length);
		}
	}

	private Map<String, String> parseTxtRecord(byte[] rdata) {
		Map<String, String> properties = new HashMap<>();
		ByteBuffer buffer = ByteBuffer.wrap(rdata);

		while (buffer.hasRemaining()) {
			int txtLength = buffer.get() & 0xFF;
			if (txtLength == 0 || buffer.remaining() < txtLength) {
				break;
			}

			byte[] txtData = new byte[txtLength];
			buffer.get(txtData);
			String txt = new String(txtData, StandardCharsets.UTF_8);

			int equalsIndex = txt.indexOf('=');
			if (equalsIndex >= 0) {
				String key = equalsIndex > 0 ? txt.substring(0, equalsIndex) : ""; //$NON-NLS-1$
				String value = equalsIndex < txt.length() - 1 ? txt.substring(equalsIndex + 1) : ""; //$NON-NLS-1$
				if (!key.isEmpty()) {
					properties.put(key, value);
				}
			}
		}

		return properties;
	}

	private void handleJenkinsService(Map<String, String> properties) {
		String url = properties.get(URL_PROPERTY);
		if (url == null) {
			notifyMessage(Messages.JenkinsDiscovery_MessageTitle,
					Messages.JenkinsDiscovery_MissingURL);
		} else {
			issueJenkinsNotification(properties);
		}
	}

	private void notifyMessage(String title, String description) {
		BuildsUi.serverDiscovered(title, description);
	}

	private void issueJenkinsNotification(Map<String, String> properties) {
		String url = properties.get(URL_PROPERTY);
		String id = getId(properties);
		if (isNew(url, id)) {
			// Change the first segment (org.eclipse.mylyn.hudson) to the id of
			// the new repository type when we start differentiation between the two
			notifyMessage(Messages.JenkinsDiscovery_MessageTitle, NLS.bind(Messages.JenkinsDiscovery_MessageText,
					url, Messages.JenkinsDiscovery_ServerName, url, id));
		}
	}

	private String getId(Map<String, String> properties) {
		String id = properties.get(SERVER_ID_PROPERTY);
		if (id == null) {
			id = UUID.randomUUID().toString();
		}
		return id;
	}

}
