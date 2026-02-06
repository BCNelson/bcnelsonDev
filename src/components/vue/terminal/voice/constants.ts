import c from 'ansi-colors';
c.enabled = true;

export const STATUS_ICONS = {
    disconnected: c.red('●'),
    connecting: c.yellow('◐'),
    ready: c.green('●'),
    calling: c.yellow('◐'),
    ringing: c.cyan('◐'),
    connected: c.green('●'),
} as const;

export const ERROR_MESSAGES = {
    NOT_READY: 'Voice service not ready. Please wait for connection.',
    ALREADY_IN_CALL: 'Already in a call. Run `voice hangup` first.',
    NO_INCOMING_CALL: 'No incoming call to answer.',
    NO_ACTIVE_CALL: 'No active call.',
    INVALID_PEER_ID: 'Invalid peer ID.',
    PEER_UNAVAILABLE: 'Peer unavailable or connection failed.',
    PERMISSION_DENIED: 'Microphone permission denied. Please allow microphone access and try again.',
    MEDIA_ERROR: 'Could not access microphone.',
    CONNECTION_FAILED: 'Connection to signaling server failed.',
    CALL_FAILED: 'Call failed.',
} as const;

export const STATUS_LABELS = {
    disconnected: 'Disconnected',
    connecting: 'Connecting...',
    ready: 'Ready',
    calling: 'Calling...',
    ringing: 'Incoming call',
    connected: 'Connected',
} as const;
