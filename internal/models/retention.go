package models

// How old messages leave the history and how their space returns to the
// disk. The defaults — every field at its zero value — are the ones that
// need no attention: retention checked every few minutes, in small steps
// that never hold up incoming messages, and the freed space handed back to
// the disk as it goes.

// The values of StorageConfig.RetentionAlign: where the age limit falls.
const (
	// AlignNone deletes what is older than the retention, to the second.
	AlignNone = ""
	// AlignDay, AlignWeek and AlignMonth move the limit back to the start of
	// its day, its week (Monday) or its month, so that only whole periods are
	// kept: with 90 days by month, the oldest month present is always complete.
	AlignDay   = "day"
	AlignWeek  = "week"
	AlignMonth = "month"
)

// The values of CleanupSchedule.Every.
const (
	// CleanupContinuous applies the retention every few minutes.
	CleanupContinuous = ""
	CleanupDaily      = "daily"
	CleanupWeekly     = "weekly"
	CleanupMonthly    = "monthly"
)

// CleanupSchedule is when the retention by age is applied. The size and
// count limits are not scheduled: they protect the disk, so they hold at all
// times.
type CleanupSchedule struct {
	Every string `json:"every,omitempty"`
	// At is the time of day, "15:04" on the machine's clock; "" is 03:00.
	At string `json:"at,omitempty"`
	// Weekday is the day of a weekly cleanup: 0 Sunday … 6 Saturday.
	Weekday int `json:"weekday,omitempty"`
	// MonthDay is the day of a monthly cleanup, 1–31; a month shorter than
	// that has it on its last day. 0 is the 1st.
	MonthDay int `json:"monthDay,omitempty"`
}

// The values of StorageConfig.Compaction: how the space of deleted messages
// goes back to the disk.
const (
	// CompactAuto gives it back in small steps after every cleanup, without
	// holding up incoming messages.
	CompactAuto = ""
	// CompactAfterCleanup rewrites the whole database after each scheduled
	// cleanup. Messages arriving meanwhile wait in memory.
	CompactAfterCleanup = "afterCleanup"
	// CompactManual leaves it to the Compact button: SQLite reuses the space
	// for new messages, but the file does not shrink.
	CompactManual = "manual"
)

// CleanupRecord is what the last cleanup did.
type CleanupRecord struct {
	At      string  `json:"at"`
	Deleted int64   `json:"deleted"`
	FreedMB float64 `json:"freedMB"`
	TookMs  int64   `json:"tookMs"`
}

// StorageForecast is where the database is heading at the rate messages
// arrive, under the retention in force. Zero values mean "not known yet".
type StorageForecast struct {
	// MessagesPerDay is measured over the last week, or the last day while
	// the history is younger than that.
	MessagesPerDay float64 `json:"messagesPerDay"`
	// BytesPerMessage is what a message takes on disk, index included.
	BytesPerMessage float64 `json:"bytesPerMessage"`
	GrowthMBPerDay  float64 `json:"growthMBPerDay"`
	// SteadyMB is the size the retention and limits hold the database at;
	// BoundBy says which one does ("age", "count", "size"), "" when none
	// does and the database grows for as long as messages arrive.
	SteadyMB float64 `json:"steadyMB"`
	BoundBy  string  `json:"boundBy,omitempty"`
	// SteadyInDays is how long until the database reaches SteadyMB.
	SteadyInDays float64 `json:"steadyInDays"`
	// FileMB is the size the file will settle at: SteadyMB when space goes
	// back to the disk, the highest the database has been otherwise.
	FileMB float64 `json:"fileMB"`
	// DiskFreeMB is the free space where the database is; DiskFullInDays is
	// when it runs out at this rate, 0 when it does not.
	DiskFreeMB     float64 `json:"diskFreeMB"`
	DiskFullInDays float64 `json:"diskFullInDays"`
}
