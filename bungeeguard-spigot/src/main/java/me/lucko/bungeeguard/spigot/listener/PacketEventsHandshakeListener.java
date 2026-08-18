/*
 * This file is part of BungeeGuard, licensed under the MIT License.
 *
 *  Copyright (c) lucko (Luck) <luck@lucko.me>
 *  Copyright (c) contributors
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

package me.lucko.bungeeguard.spigot.listener;

import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.protocol.ConnectionState;
import com.github.retrooper.packetevents.wrapper.handshaking.client.WrapperHandshakingClientHandshake;

import me.lucko.bungeeguard.backend.BungeeGuardBackend;
import me.lucko.bungeeguard.backend.TokenStore;
import me.lucko.bungeeguard.backend.listener.AbstractHandshakeListener;
import me.lucko.bungeeguard.spigot.BungeeCordHandshake;

import org.bukkit.plugin.Plugin;

import java.net.InetSocketAddress;
import java.util.logging.Level;

/**
 * A handshake listener using PacketEvents.
 */
public class PacketEventsHandshakeListener extends AbstractHandshakeListener {

    public PacketEventsHandshakeListener(BungeeGuardBackend plugin, TokenStore tokenStore) {
        super(plugin, tokenStore);
    }

    public void registerAdapter(Plugin plugin) {
        PacketEvents.getAPI().getEventManager().registerListener(new Adapter(plugin));
    }

    private final class Adapter extends PacketListenerAbstract {
        private final Plugin plugin;

        Adapter(Plugin plugin) {
            super(PacketListenerPriority.LOWEST);
            this.plugin = plugin;
            plugin.getLogger().info("Using PacketEvents v2 adapter.");
        }

        @Override
        public void onPacketReceive(PacketReceiveEvent event) {
            if (event.getPacketType() != PacketType.Handshaking.Client.HANDSHAKE) {
                return;
            }

            WrapperHandshakingClientHandshake handshake = new WrapperHandshakingClientHandshake(event);

            // only handle the LOGIN phase
            if (handshake.getNextConnectionState() != ConnectionState.LOGIN) {
                return;
            }

            String originalHandshake = handshake.getServerAddress();
            BungeeCordHandshake decoded = BungeeCordHandshake.decodeAndVerify(originalHandshake, PacketEventsHandshakeListener.this.tokenStore);

            if (decoded instanceof BungeeCordHandshake.Fail) {
                String ip = "null";
                Object channel = event.getChannel();
                if (channel != null) {
                    try {
                        ip = channel.toString(); // basic fallback, if possible we could parse it
                    } catch (Exception ignored) {}
                }
                
                BungeeCordHandshake.Fail fail = (BungeeCordHandshake.Fail) decoded;
                this.plugin.getLogger().warning("Denying connection from " + ip + " - " + fail.describeConnection() + " - reason: " + fail.reason().name());

                try {
                    // Just close the connection since we are in handshake state
                    event.getUser().closeConnection();
                } catch (Exception e) {
                    this.plugin.getLogger().log(Level.SEVERE, "An error occurred while closing connection", e);
                }

                // screw up the hostname so Spigot can't pick up anything spoofed
                handshake.setServerAddress("null");

                return;
            }

            // great, handshake was decoded and verified successfully.
            BungeeCordHandshake.Success data = (BungeeCordHandshake.Success) decoded;
            handshake.setServerAddress(data.encode());
        }
    }
}
