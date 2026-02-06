export type VoiceStatus =
    | 'disconnected'
    | 'connecting'
    | 'ready'
    | 'calling'
    | 'ringing'
    | 'connected';

export interface CallMetadata {
    callerName?: string;
}

export interface VoiceState {
    status: VoiceStatus;
    peerId: string | null;
    remotePeerId: string | null;
    isMuted: boolean;
    callStartTime: number | null;
}

export type VoiceEventType =
    | 'status-change'
    | 'incoming-call'
    | 'call-connected'
    | 'call-ended'
    | 'error';

export interface VoiceEvent {
    type: VoiceEventType;
    data?: {
        peerId?: string;
        error?: string;
        previousStatus?: VoiceStatus;
        newStatus?: VoiceStatus;
    };
}

export type VoiceEventHandler = (event: VoiceEvent) => void;
