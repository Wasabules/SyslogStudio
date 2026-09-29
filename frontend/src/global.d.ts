interface Window {
    runtime?: {
        // Registering this is what installs the drag listeners. Without the
        // call there is no drop handling at all, whatever the Go side enables.
        OnFileDrop?: (
            callback: (x: number, y: number, paths: string[]) => void,
            useDropTarget: boolean,
        ) => void;
        OnFileDropOff?: () => void;
        EventsOnMultiple: (eventName: string, callback: (...args: any[]) => void, maxCallbacks: number) => void;
        EventsOff: (eventName: string, ...additionalEventNames: string[]) => void;
        [key: string]: any;
    };
    go?: {
        [key: string]: any;
    };
}
