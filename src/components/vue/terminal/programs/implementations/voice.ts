import type { ProgramInterface, Context } from '../interface';
import type { Program } from '../base';
import c from 'ansi-colors';
import { STATUS_ICONS, STATUS_LABELS, ERROR_MESSAGES } from '../../voice/constants';
c.enabled = true;

const SUBCOMMANDS = ['id', 'call', 'answer', 'hangup', 'reject', 'mute', 'unmute', 'status'] as const;
type Subcommand = typeof SUBCOMMANDS[number];

function showUsage(pi: ProgramInterface): Promise<number> {
    return (async () => {
        await pi.writeln('Usage: voice <subcommand>');
        await pi.writeln('');
        await pi.writeln('Subcommands:');
        await pi.writeln('  id        Display your peer ID');
        await pi.writeln('  call      Call another peer: voice call <peer-id>');
        await pi.writeln('  answer    Accept incoming call');
        await pi.writeln('  hangup    End current call');
        await pi.writeln('  reject    Reject incoming call');
        await pi.writeln('  mute      Mute microphone');
        await pi.writeln('  unmute    Unmute microphone');
        await pi.writeln('  status    Show call status');
        return 0;
    })();
}

async function handleId(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;
    const state = voice.getState();

    if (!state.peerId) {
        await pi.writeln(c.yellow('Connecting to voice service...'));
        try {
            await voice.initialize();
        } catch (e) {
            await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.CONNECTION_FAILED}`));
            return 1;
        }
    }

    const peerId = voice.getState().peerId;
    await pi.writeln(`Your peer ID: ${c.cyan(peerId!)}`);
    await pi.writeln(c.gray('Share this ID with others to receive calls.'));
    return 0;
}

async function handleCall(pi: ProgramInterface, remotePeerId: string | undefined): Promise<number> {
    if (!remotePeerId) {
        await pi.writeln(c.red('Usage: voice call <peer-id>'));
        return 1;
    }

    const voice = pi.voiceService;
    const state = voice.getState();

    if (state.status === 'disconnected' || state.status === 'connecting') {
        await pi.writeln(c.yellow('Connecting to voice service...'));
        try {
            await voice.initialize();
        } catch (e) {
            await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.CONNECTION_FAILED}`));
            return 1;
        }
    }

    await pi.writeln(`Calling ${c.cyan(remotePeerId)}...`);

    try {
        await voice.call(remotePeerId);
    } catch (e) {
        await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.CALL_FAILED}`));
        return 1;
    }

    return 0;
}

async function handleAnswer(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;

    try {
        await voice.answer();
        await pi.writeln(c.green('Call connected!'));
    } catch (e) {
        await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.NO_INCOMING_CALL}`));
        return 1;
    }

    return 0;
}

async function handleHangup(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;

    try {
        const duration = voice.getCallDuration();
        voice.hangup();
        await pi.writeln(c.yellow(`Call ended. Duration: ${voice.formatDuration(duration)}`));
    } catch (e) {
        await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.NO_ACTIVE_CALL}`));
        return 1;
    }

    return 0;
}

async function handleReject(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;

    try {
        voice.reject();
        await pi.writeln(c.yellow('Call rejected.'));
    } catch (e) {
        await pi.writeln(c.red(`Error: ${e instanceof Error ? e.message : ERROR_MESSAGES.NO_INCOMING_CALL}`));
        return 1;
    }

    return 0;
}

async function handleMute(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;
    const state = voice.getState();

    if (state.status !== 'connected') {
        await pi.writeln(c.red('Error: Not in a call.'));
        return 1;
    }

    voice.mute();
    await pi.writeln(c.yellow('Microphone muted.'));
    return 0;
}

async function handleUnmute(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;
    const state = voice.getState();

    if (state.status !== 'connected') {
        await pi.writeln(c.red('Error: Not in a call.'));
        return 1;
    }

    voice.unmute();
    await pi.writeln(c.green('Microphone unmuted.'));
    return 0;
}

async function handleStatus(pi: ProgramInterface): Promise<number> {
    const voice = pi.voiceService;
    const state = voice.getState();

    const icon = STATUS_ICONS[state.status];
    const label = STATUS_LABELS[state.status];

    await pi.writeln(`Status: ${icon} ${label}`);

    if (state.peerId) {
        await pi.writeln(`Peer ID: ${c.cyan(state.peerId)}`);
    }

    if (state.remotePeerId) {
        await pi.writeln(`Remote: ${c.cyan(state.remotePeerId)}`);
    }

    if (state.status === 'connected') {
        const duration = voice.getCallDuration();
        await pi.writeln(`Duration: ${voice.formatDuration(duration)}`);
        await pi.writeln(`Muted: ${state.isMuted ? c.yellow('Yes') : c.green('No')}`);
    }

    return 0;
}

export default {
    run: async (programInterface: ProgramInterface): Promise<number> => {
        const args = programInterface.args.slice(1);
        const subcommand = args[0] as Subcommand | undefined;

        if (!subcommand) {
            return showUsage(programInterface);
        }

        switch (subcommand) {
            case 'id':
                return handleId(programInterface);
            case 'call':
                return handleCall(programInterface, args[1]);
            case 'answer':
                return handleAnswer(programInterface);
            case 'hangup':
                return handleHangup(programInterface);
            case 'reject':
                return handleReject(programInterface);
            case 'mute':
                return handleMute(programInterface);
            case 'unmute':
                return handleUnmute(programInterface);
            case 'status':
                return handleStatus(programInterface);
            default:
                await programInterface.writeln(c.red(`Unknown subcommand: ${subcommand}`));
                return showUsage(programInterface);
        }
    },
    suggest: async (context: Context): Promise<string> => {
        // Suggest subcommands if we're completing the first argument
        if (context.tokenIndex === 1) {
            const matching = SUBCOMMANDS.filter(s => s.startsWith(context.partial));
            if (matching.length === 1) {
                return matching[0];
            }
        }
        return '';
    },
    description: 'Voice calling via WebRTC',
} as Program;
