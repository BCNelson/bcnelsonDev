let connectSound: HTMLAudioElement | null = null;
let disconnectSound: HTMLAudioElement | null = null;

export function preloadSounds(): void {
    if (!connectSound) {
        connectSound = new Audio('/sounds/connect.mp3');
        connectSound.load();
    }
    if (!disconnectSound) {
        disconnectSound = new Audio('/sounds/disconnect.mp3');
        disconnectSound.load();
    }
}

export function playConnectSound(): void {
    if (!connectSound) {
        connectSound = new Audio('/sounds/connect.mp3');
    }
    connectSound.currentTime = 0;
    connectSound.play().catch((e) => {
        console.error('Failed to play connect sound:', e);
    });
}

export function playDisconnectSound(): void {
    if (!disconnectSound) {
        disconnectSound = new Audio('/sounds/disconnect.mp3');
    }
    disconnectSound.currentTime = 0;
    disconnectSound.play().catch((e) => {
        console.error('Failed to play disconnect sound:', e);
    });
}
