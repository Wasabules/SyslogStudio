interface Window {
    runtime?: {
        EventsOnMultiple: (eventName: string, callback: (...args: any[]) => void, maxCallbacks: number) => void;
        EventsOff: (eventName: string, ...additionalEventNames: string[]) => void;
        [key: string]: any;
    };
    go?: {
        [key: string]: any;
    };
}
