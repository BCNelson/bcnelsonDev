declare var umami: umami.umami;

// Based on https://umami.is/docs/tracker-functions
declare namespace umami {
    interface umami {
        (event_value: string): void;
        trackEvent(event_value: string, event_type: Record<string, any>, url?: string, website_id?: string): void;
        trackView(url: string, referrer?: string, website_id?: string): void;
    }
}