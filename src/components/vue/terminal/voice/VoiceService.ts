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

export class VoiceService {
    private static instance: VoiceService | null = null;

    private peer: Peer | null = null;
    private currentCall: MediaConnection | null = null;
    private localStream: MediaStream | null = null;
    private remoteAudio: HTMLAudioElement | null = null;
    private incomingCall: MediaConnection | null = null;

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
        if (this.peer && !this.peer.destroyed) {
            return;
        }

        this.setStatus('connecting');

        return new Promise((resolve, reject) => {
            this.peer = new Peer();

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
        if (!this.incomingCall) {
            throw new Error(ERROR_MESSAGES.NO_INCOMING_CALL);
        }

        this.incomingCall.close();
        this.incomingCall = null;
        this.state.remotePeerId = null;
        this.setStatus('ready');
    }

    hangup(): void {
        if (!this.currentCall && !this.incomingCall) {
            throw new Error(ERROR_MESSAGES.NO_ACTIVE_CALL);
        }

        const duration = this.getCallDuration();

        if (this.currentCall) {
            this.currentCall.close();
        }
        if (this.incomingCall) {
            this.incomingCall.close();
        }

        this.cleanupCall();
        this.emit({
            type: 'call-ended',
            data: { peerId: this.state.remotePeerId ?? undefined },
        });
    }

    mute(): void {
        if (this.localStream) {
            for (const track of this.localStream.getAudioTracks()) {
                track.enabled = false;
            }
        }
        this.state.isMuted = true;
    }

    unmute(): void {
        if (this.localStream) {
            for (const track of this.localStream.getAudioTracks()) {
                track.enabled = true;
            }
        }
        this.state.isMuted = false;
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
            this.cleanupCall();
            this.emit({
                type: 'call-ended',
                data: { peerId: call.peer },
            });
        });

        call.on('error', (err) => {
            console.error('Call error:', err);
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
        this.eventHandlers.clear();
    }
}
