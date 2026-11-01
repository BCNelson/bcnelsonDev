import Peer, { type MediaConnection, type PeerError } from 'peerjs';
import type {
    VoiceState,
    VoiceStatus,
    VoiceEvent,
    VoiceEventHandler,
    CallMetadata,
} from './types';
import { ERROR_MESSAGES } from './constants';
import { playConnectSound, playDisconnectSound, preloadSounds } from './sounds';
import { generateShortId } from './crockford';

const PEER_ID_KEY = 'voice_peer_id';
// Tabs share the peer ID via localStorage, but the signaling server allows one
// connection per ID. The tab holding this lock (the leader) owns the connection
// and mirrors its state to the other tabs over the broadcast channel.
const PEER_LOCK_NAME = 'voice_peer_connection';
const CHANNEL_NAME = 'voice_service';
const LEADER_STATE_TIMEOUT_MS = 1000;
// Statuses in which the leader's connection can't be handed to another tab
const BUSY_STATUSES: ReadonlySet<VoiceStatus> = new Set(['calling', 'ringing', 'connected']);

type ChannelMessage =
    | { type: 'state-request' }
    | { type: 'state'; state: VoiceState }
    | { type: 'event'; event: VoiceEvent; state: VoiceState };

export class VoiceService {
    private static instance: VoiceService | null = null;

    private peer: Peer | null = null;
    private currentCall: MediaConnection | null = null;
    private localStream: MediaStream | null = null;
    private remoteAudio: HTMLAudioElement | null = null;
    private incomingCall: MediaConnection | null = null;

    private channel: BroadcastChannel | null = null;
    private isLeader = false;
    private starting: Promise<void> | null = null;
    private queuedLock: AbortController | null = null;
    private releaseLock: (() => void) | null = null;
    private onRoleSettled: (() => void) | null = null;

    private state: VoiceState = {
        status: 'disconnected',
        peerId: null,
        remotePeerId: null,
        isMuted: false,
        callStartTime: null,
    };

    private eventHandlers: Set<VoiceEventHandler> = new Set();

    private constructor() {}

    static getInstance(): VoiceService {
        if (!VoiceService.instance) {
            VoiceService.instance = new VoiceService();
        }
        return VoiceService.instance;
    }

    getState(): Readonly<VoiceState> {
        return { ...this.state };
    }

    subscribe(handler: VoiceEventHandler): () => void {
        this.eventHandlers.add(handler);
        return () => this.eventHandlers.delete(handler);
    }

    private emit(event: VoiceEvent): void {
        this.dispatch(event);
        if (this.isLeader) {
            this.post({ type: 'event', event, state: this.state });
        }
    }

    private dispatch(event: VoiceEvent): void {
        for (const handler of this.eventHandlers) {
            try {
                handler(event);
            } catch (e) {
                console.error('VoiceService event handler error:', e);
            }
        }
    }

    private setStatus(status: VoiceStatus): void {
        const previousStatus = this.state.status;
        this.state.status = status;
        this.emit({
            type: 'status-change',
            data: { previousStatus, newStatus: status },
        });
    }

    async initialize(): Promise<void> {
        await this.start();

        if (this.isLeader) {
            return this.connect();
        }

        // The leader tab has no working connection, so take it over
        if (this.state.status === 'disconnected') {
            await this.takeLead();
        }
    }

    private start(): Promise<void> {
        this.starting ??= (async () => {
            if (!navigator.locks || typeof BroadcastChannel === 'undefined') {
                // No way to coordinate tabs; every tab connects on its own
                this.isLeader = true;
                return;
            }

            this.channel = new BroadcastChannel(CHANNEL_NAME);
            this.channel.onmessage = (e: MessageEvent<ChannelMessage>) => this.handleChannelMessage(e.data);

            if (await this.acquireLock({ ifAvailable: true })) {
                return;
            }

            // Another tab leads: wait in line to succeed it and mirror its state
            this.queueLock();
            await new Promise<void>((resolve) => {
                const timer = setTimeout(resolve, LEADER_STATE_TIMEOUT_MS);
                this.onRoleSettled = () => {
                    clearTimeout(timer);
                    resolve();
                };
                this.post({ type: 'state-request' });
            });
            this.onRoleSettled = null;
        })();
        return this.starting;
    }

    private acquireLock(options: LockOptions): Promise<boolean> {
        return new Promise((resolve) => {
            let granted = false;
            navigator.locks.request(PEER_LOCK_NAME, options, (lock) => {
                if (!lock) {
                    resolve(false);
                    return;
                }
                granted = true;
                this.becomeLeader();
                resolve(true);
                // Hold the lock until destroy(), the tab closes, or another tab steals it
                return new Promise<void>((release) => {
                    this.releaseLock = release;
                });
            }).catch(() => {
                // Aborted while queued, or stolen by a tab that took over
                if (granted) {
                    this.stepDown();
                }
                resolve(false);
            });
        });
    }

    private queueLock(): void {
        if (this.queuedLock) {
            return;
        }
        const controller = new AbortController();
        this.queuedLock = controller;
        void this.acquireLock({ signal: controller.signal }).then((granted) => {
            if (this.queuedLock === controller) {
                this.queuedLock = null;
            }
            if (granted) {
                // The previous leader tab closed; keep the peer ID reachable
                this.connect().catch(() => {});
            }
        });
    }

    private async takeLead(): Promise<void> {
        this.queuedLock?.abort();
        this.queuedLock = null;
        await this.acquireLock({ steal: true });
        await this.connect();
    }

    private becomeLeader(): void {
        this.isLeader = true;
        this.onRoleSettled?.();
    }

    private stepDown(): void {
        this.isLeader = false;
        this.releaseLock = null;
        if (this.peer) {
            // Drop the connection without the handlers reconnecting it
            const peer = this.peer;
            this.peer = null;
            peer.removeAllListeners();
            peer.destroy();
        }
        this.queueLock();
    }

    private post(message: ChannelMessage): void {
        this.channel?.postMessage(message);
    }

    private handleChannelMessage(message: ChannelMessage): void {
        if (message.type === 'state-request') {
            if (this.isLeader) {
                this.post({ type: 'state', state: this.state });
            }
            return;
        }

        if (this.isLeader) {
            return;
        }

        const previousStatus = this.state.status;
        this.state = { ...message.state };

        if (message.type === 'event') {
            this.dispatch(message.event);
        } else {
            this.onRoleSettled?.();
            if (previousStatus !== this.state.status) {
                this.dispatch({
                    type: 'status-change',
                    data: { previousStatus, newStatus: this.state.status },
                });
            }
        }
    }

    // Throws if a call is in progress in another tab
    private assertNotBusyElsewhere(): void {
        if (!this.isLeader && BUSY_STATUSES.has(this.state.status)) {
            throw new Error(ERROR_MESSAGES.ACTIVE_IN_OTHER_TAB);
        }
    }

    private async connect(): Promise<void> {
        if (this.peer && !this.peer.destroyed) {
            return;
        }

        this.setStatus('connecting');

        // Get or generate persistent peer ID
        let peerId = localStorage.getItem(PEER_ID_KEY);
        if (!peerId) {
            peerId = generateShortId(40); // 8 characters
            localStorage.setItem(PEER_ID_KEY, peerId);
        }

        return new Promise((resolve, reject) => {
            this.peer = new Peer(peerId, {
                host: 'bcnelson.dev',
                port: 443,
                path: '/peer',
                secure: true,
            });

            this.peer.on('open', (id) => {
                this.state.peerId = id;
                this.setStatus('ready');
                resolve();
            });

            this.peer.on('error', (err: PeerError<string>) => {
                console.error('PeerJS error:', err);
                if (this.state.status === 'connecting') {
                    this.setStatus('disconnected');
                    reject(new Error(ERROR_MESSAGES.CONNECTION_FAILED));
                } else {
                    this.emit({
                        type: 'error',
                        data: { error: err.message },
                    });
                }
            });

            this.peer.on('call', (call) => {
                this.handleIncomingCall(call);
            });

            this.peer.on('disconnected', () => {
                if (this.state.status !== 'disconnected') {
                    this.peer?.reconnect();
                }
            });

            this.peer.on('close', () => {
                this.cleanup();
                this.setStatus('disconnected');
            });
        });
    }

    private handleIncomingCall(call: MediaConnection): void {
        if (this.currentCall) {
            // Already in a call, reject the incoming one
            call.close();
            return;
        }

        this.incomingCall = call;
        this.state.remotePeerId = call.peer;
        this.setStatus('ringing');

        this.emit({
            type: 'incoming-call',
            data: { peerId: call.peer },
        });

        // Set up call handlers even before answering
        call.on('close', () => {
            if (this.incomingCall === call) {
                this.incomingCall = null;
                if (this.state.status === 'ringing') {
                    this.state.remotePeerId = null;
                    this.setStatus('ready');
                }
            }
        });
    }

    async call(remotePeerId: string): Promise<void> {
        if (!remotePeerId || remotePeerId.trim() === '') {
            throw new Error(ERROR_MESSAGES.INVALID_PEER_ID);
        }

        this.assertNotBusyElsewhere();
        if (!this.isLeader) {
            // Media has to live in this tab, so move the connection here
            await this.takeLead();
        }

        if (this.state.status !== 'ready') {
            if (this.state.status === 'disconnected' || this.state.status === 'connecting') {
                throw new Error(ERROR_MESSAGES.NOT_READY);
            }
            throw new Error(ERROR_MESSAGES.ALREADY_IN_CALL);
        }

        this.setStatus('calling');
        this.state.remotePeerId = remotePeerId;
        preloadSounds();

        try {
            await this.acquireMedia();
        } catch {
            this.state.remotePeerId = null;
            this.setStatus('ready');
            throw new Error(ERROR_MESSAGES.PERMISSION_DENIED);
        }

        if (!this.peer || !this.localStream) {
            this.state.remotePeerId = null;
            this.setStatus('ready');
            throw new Error(ERROR_MESSAGES.CALL_FAILED);
        }

        const call = this.peer.call(remotePeerId, this.localStream);
        this.setupCallHandlers(call);
    }

    async answer(): Promise<void> {
        this.assertNotBusyElsewhere();
        if (!this.incomingCall) {
            throw new Error(ERROR_MESSAGES.NO_INCOMING_CALL);
        }

        preloadSounds();

        try {
            await this.acquireMedia();
        } catch {
            throw new Error(ERROR_MESSAGES.PERMISSION_DENIED);
        }

        if (!this.localStream) {
            throw new Error(ERROR_MESSAGES.MEDIA_ERROR);
        }

        const call = this.incomingCall;
        this.incomingCall = null;

        call.answer(this.localStream);
        this.setupCallHandlers(call);
    }

    reject(): void {
        this.assertNotBusyElsewhere();
        if (!this.incomingCall) {
            throw new Error(ERROR_MESSAGES.NO_INCOMING_CALL);
        }

        this.incomingCall.close();
        this.incomingCall = null;
        this.state.remotePeerId = null;
        this.setStatus('ready');
    }

    hangup(): void {
        this.assertNotBusyElsewhere();
        if (!this.currentCall && !this.incomingCall) {
            throw new Error(ERROR_MESSAGES.NO_ACTIVE_CALL);
        }

        const calls = [this.currentCall, this.incomingCall];
        // End first so the calls' close handlers see they're no longer current
        this.endCall();
        for (const call of calls) {
            call?.close();
        }
    }

    // Cleans up the current call and announces its end once
    private endCall(): void {
        const peerId = this.state.remotePeerId ?? undefined;
        const duration = this.state.callStartTime ? this.getCallDuration() : undefined;
        this.cleanupCall();
        this.emit({
            type: 'call-ended',
            data: { peerId, duration },
        });
    }

    mute(): void {
        this.assertNotBusyElsewhere();
        if (this.localStream) {
            for (const track of this.localStream.getAudioTracks()) {
                track.enabled = false;
            }
        }
        this.state.isMuted = true;
        this.post({ type: 'state', state: this.state });
    }

    unmute(): void {
        this.assertNotBusyElsewhere();
        if (this.localStream) {
            for (const track of this.localStream.getAudioTracks()) {
                track.enabled = true;
            }
        }
        this.state.isMuted = false;
        this.post({ type: 'state', state: this.state });
    }

    getCallDuration(): number {
        if (!this.state.callStartTime) {
            return 0;
        }
        return Math.floor((Date.now() - this.state.callStartTime) / 1000);
    }

    formatDuration(seconds: number): string {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    private async acquireMedia(): Promise<void> {
        if (this.localStream) {
            return;
        }

        this.localStream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false,
        });
    }

    private setupCallHandlers(call: MediaConnection): void {
        this.currentCall = call;

        call.on('stream', (remoteStream) => {
            this.playRemoteStream(remoteStream);
            this.state.callStartTime = Date.now();
            this.setStatus('connected');
            playConnectSound();
            this.emit({
                type: 'call-connected',
                data: { peerId: call.peer },
            });
        });

        call.on('close', () => {
            if (this.currentCall === call) {
                this.endCall();
            }
        });

        call.on('error', (err) => {
            console.error('Call error:', err);
            if (this.currentCall !== call) {
                return;
            }
            this.cleanupCall();
            this.emit({
                type: 'error',
                data: { error: ERROR_MESSAGES.CALL_FAILED },
            });
        });
    }

    private playRemoteStream(stream: MediaStream): void {
        if (!this.remoteAudio) {
            this.remoteAudio = new Audio();
        }
        this.remoteAudio.srcObject = stream;
        this.remoteAudio.play().catch((e) => {
            console.error('Failed to play remote audio:', e);
        });
    }

    private cleanupCall(): void {
        const wasConnected = this.state.status === 'connected';

        this.currentCall = null;
        this.incomingCall = null;
        this.state.remotePeerId = null;
        this.state.callStartTime = null;
        this.state.isMuted = false;

        if (wasConnected) {
            playDisconnectSound();
        }

        if (this.localStream) {
            for (const track of this.localStream.getTracks()) {
                track.stop();
            }
            this.localStream = null;
        }

        if (this.remoteAudio) {
            this.remoteAudio.srcObject = null;
        }

        if (this.peer && !this.peer.destroyed) {
            this.setStatus('ready');
        } else {
            this.setStatus('disconnected');
        }
    }

    private cleanup(): void {
        this.cleanupCall();
        this.state.peerId = null;
    }

    destroy(): void {
        this.cleanup();
        if (this.peer) {
            this.peer.destroy();
            this.peer = null;
        }
        this.queuedLock?.abort();
        this.queuedLock = null;
        this.releaseLock?.();
        this.releaseLock = null;
        this.isLeader = false;
        this.channel?.close();
        this.channel = null;
        this.starting = null;
        this.eventHandlers.clear();
    }
}
