package vault

// syncDir has nothing to do on Windows, where a rename is written through.
func syncDir(string) {}
